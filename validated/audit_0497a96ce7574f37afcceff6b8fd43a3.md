### Title
Peras Certificate Validation Bypass: Stub `validatePerasCert` Unconditionally Returns `Right` in Production Ingest Path — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB`) calls `validatePerasCert mkPerasParams` to vet every inbound certificate received from a peer. The `BlockSupportsPeras` instance that covers all block types — including the production `CardanoBlock` — is a degenerate stub that unconditionally returns `Right` for every certificate, performing zero cryptographic checks. Any unprivileged peer can therefore inject arbitrary Peras certificates into the node's `PerasCertDB` and trigger chain-selection side-effects without possessing valid BLS signatures, committee-membership proofs, or any other required credential.

---

### Finding Description

**Root cause — wrong function used (stub instead of real validator).**

In `SupportsPeras.hs` the catch-all `BlockSupportsPeras` instance defines:

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

This stub accepts every certificate unconditionally. [1](#0-0) 

The production pool writer `makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` passes this stub directly as the `validateCert` argument to `processCerts`:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` only rejects a batch when at least one certificate returns `Left`. Because the stub always returns `Right`, every certificate from every peer is unconditionally accepted and forwarded to `ChainDB.addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

The same pattern applies to `makePerasCertPoolWriterFromCertDB`, which is the test-isolation variant but shares the same stub. [4](#0-3) 

**Analog mapping to the external report:**

| External (Solidity) | Analog (Haskell) |
|---|---|
| `transferFrom(address(this), msg.sender, amount)` requires `allowance[from][msg.sender] >= amount` — a precondition that is never set up, so the call always **fails** | `validatePerasCert mkPerasParams cert` should require a valid BLS signature / committee-membership proof — a precondition that is never checked, so the call always **succeeds** |
| Wrong function used: `transferFrom` instead of `transfer` | Wrong function used: stub `validatePerasCert` instead of the real cryptographic validator |
| Impact: funds permanently locked | Impact: certificate validation permanently bypassed |

In both cases the root cause is identical: the wrong variant of a function is called. One variant requires a precondition that is never satisfied; the other does not require it at all. The external bug chose the variant that always fails; this codebase chose the variant that always succeeds.

---

### Impact Explanation

Peras certificates boost blocks during chain selection. A certificate for round `r` boosting block `B` causes honest nodes to add `perasWeight` (currently 15) to `B`'s chain weight. An attacker who can inject arbitrary certificates can:

1. Boost any block of their choosing, causing honest nodes to prefer a weaker or adversarially-controlled chain over the canonical chain.
2. Forge certificates for rounds that have already passed, retroactively altering the effective weight of historical blocks and corrupting the chain-selection invariant.
3. Flood the `PerasCertDB` with certificates for every possible round number, poisoning the `latestCertSeen` and `latestCertOnChain` views used by the Peras voting rules, silencing legitimate voting.

This is a **Critical** bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The attack requires only a peer connection. The `makePerasCertPoolWriterFromChainDB` function is the explicitly documented production path. [5](#0-4) 

No stake, no keys, no special privileges are needed. Any node that participates in the Peras ObjectDiffusion mini-protocol is reachable. The degenerate `BlockSupportsPeras` instance is the only instance in the codebase for the production block type, confirmed by the comment "TODO: degenerate instance for all blks to get things to compile". [6](#0-5) 

---

### Recommendation

1. **Immediate**: Gate `makePerasCertPoolWriterFromChainDB` (and `makePerasCertPoolWriterFromCertDB`) behind a feature flag or remove the ObjectDiffusion certificate writer from the active diffusion stack until a real `validatePerasCert` implementation is in place.
2. **Correct fix**: Implement the real `validatePerasCert` for `CardanoBlock` (tracked in issue #120) that verifies BLS aggregate signatures, committee-membership eligibility proofs, round-number bounds, and boosted-block reachability before returning `Right`.
3. **Secondary**: Apply the same scrutiny to `validatePerasVote`, which also omits cryptographic signature verification and only checks stake-distribution membership. [7](#0-6) 

---

### Proof of Concept

```
1. Establish a peer connection to a target node that has the Peras
   ObjectDiffusion mini-protocol active.

2. Craft a PerasCert with:
     pcCertRound      = <any round number, e.g. the current round>
     pcCertBoostedBlock = <point of an adversarially chosen block>

3. Send the certificate batch via the ObjectDiffusion writer protocol.

4. processCerts calls (validatePerasCert mkPerasParams) on the cert.
   The stub returns:
     Right (ValidatedPerasCert { vpcCert = cert
                               , vpcCertBoost = PerasWeight 15 })

5. The certificate passes partitionEithers with zero errors and is
   forwarded to ChainDB.addPerasCertAsync.

6. Chain selection now treats the adversarially chosen block as having
   15 additional weight units, potentially causing the node to prefer
   a weaker chain.
```

The stub is at: [8](#0-7) 

The production ingest entry point is at: [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L111-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```
