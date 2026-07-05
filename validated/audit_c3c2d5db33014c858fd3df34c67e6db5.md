### Title
Peras Certificate Validation Bypass Allows Peer-Injected Weight Boosts to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing no cryptographic or structural checks. Both production certificate-pool writers pass this stub directly as the validator for peer-supplied certificates. An unprivileged peer can therefore inject an arbitrary `PerasCert` — pointing to any block hash and any round number — which will be accepted, stored, and used to apply a Peras weight boost during chain selection.

---

### Finding Description

`SupportsPeras.hs` defines a catch-all `instance StandardHash blk => BlockSupportsPeras blk` (line 320, marked with the comment *"TODO: degenerate instance for all blks to get things to compile"*). Its `validatePerasCert` implementation is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No signature verification, no committee-membership check, no round-number or boosted-block sanity check is performed. Every certificate, regardless of content, is returned as `ValidatedPerasCert` carrying the full `perasWeight params` boost. [1](#0-0) 

This stub is wired directly into both production certificate-pool writers in `PerasCert.hs`:

```haskell
-- makePerasCertPoolWriterFromCertDB (line 103)
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB (line 126)
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls the supplied validator on every inbound certificate from a peer; if all pass (which they always do here), each is timestamped and forwarded to `addCert`: [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` then calls `ChainDB.addPerasCertAsync`, which triggers chain-selection side-effects. Chain selection in `ChainSel.hs` consults the Peras weight snapshot (`weights`) when comparing candidate fragments: [4](#0-3) 

The analog to the original report is exact: just as any caller could set `referral` to a self-controlled address and receive `referralFee` without authorization, any peer can set `pcCertBoostedBlock` to an attacker-controlled block hash and receive a full `perasWeight` chain-selection boost without any cryptographic authorization.

---

### Impact Explanation

A peer that sends a crafted `PerasCert` with an arbitrary `pcCertBoostedBlock` causes the local node to:

1. Accept the certificate unconditionally (no signature or committee check).
2. Store it in `PerasCertDB` / `ChainDB` as a `ValidatedPerasCert` carrying the full Peras weight boost.
3. Apply that boost to the attacker-specified block during `preferAnchoredCandidate`, potentially making an adversarial chain appear heavier than the honest chain.

This is a **bypass of Peras certificate validation** that enables unauthorized certificate acceptance and chain-selection weight manipulation — matching the "Critical: Bypass of … certificate … checks … that enables unauthorized … certificate acceptance" impact class.

---

### Likelihood Explanation

The object-diffusion miniprotocol for Peras certificates is reachable by any unprivileged peer that connects to the node. No stake, no key material, and no prior authentication is required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` message. The stub is the only implementation in the codebase for the block types used in production (the catch-all instance covers all `StandardHash blk`), and both production writers use it with explicit TODO comments acknowledging the missing validation.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature against the declared voter set and the `(pcCertRound, pcCertBoostedBlock)` message.
2. Checks that the declared voters constitute a valid quorum of the committee for the given round.
3. Confirms `pcCertBoostedBlock` refers to a block that is actually on a known chain fragment.

Until the real implementation is in place, the object-diffusion inbound path for Peras certificates should refuse all peer-supplied certificates (return a hard error rather than `Right`) so that the stub cannot be exploited.

---

### Proof of Concept

An attacker peer:

1. Connects to a target node via the Peras object-diffusion miniprotocol.
2. Sends a single `PerasCert` message:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <adversarial block hash> }
   ```
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
4. The certificate is stored and `ChainDB.addPerasCertAsync` is called, updating the `PerasWeightSnapshot`.
5. On the next chain-selection run, `preferAnchoredCandidate bcfg weights curChain` applies the injected boost to the adversarial block, potentially causing the node to prefer the adversarial chain over the honest chain. [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1132)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
```
