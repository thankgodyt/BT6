### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Accepting All Inbound Peer Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every certificate, performing zero cryptographic or structural checks. `processCerts` in the Peras object-diffusion layer calls this function on every certificate received from an untrusted NTN peer before inserting it into the cert database. Because the validator never rejects, any unprivileged peer can inject arbitrary Peras certificates for any round and any block, bypassing the Peras certificate-verification gate entirely and directly influencing chain selection.

### Finding Description

**Root cause — stub validator always succeeds:** [1](#0-0) 

The universal instance comment reads *"TODO: degenerate instance for all blks to get things to compile"* and the `validatePerasCert` body is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

It wraps the raw peer-supplied `PerasCert` directly into a `ValidatedPerasCert` without inspecting any field. No signature, no committee membership, no round-range, no boosted-block plausibility check is performed.

**Inbound path — `processCerts` trusts the stub result:** [2](#0-1) 

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter ... certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
```

`validateCert` is bound to `validatePerasCert mkPerasParams` at both call sites: [3](#0-2) 

Because the stub always returns `[]` errors, every cert in the batch passes the `([], validatedCerts)` branch and is unconditionally inserted into the ChainDB via `ChainDB.addPerasCertAsync`.

**Contrast with `processVotes`:** The vote path performs deduplication *and* validation atomically inside a single STM transaction, and `validatePerasVote` at least checks stake-distribution membership before accepting a vote: [4](#0-3) [5](#0-4) 

The certificate path has no equivalent guard.

**Additional asymmetry — non-atomic deduplication in `processCerts`:**

Unlike `processVotes`, `processCerts` reads `alreadyInDb` in one `atomically` call and then calls `addCert` outside that transaction. Two concurrent peers sending certs for the same round can both pass the deduplication filter and both reach `addCert`, potentially inserting conflicting certs for the same round. [6](#0-5) 

### Impact Explanation

Peras certificates boost specific blocks in chain selection, giving them additional weight (`vpcCertBoost = perasWeight params`). Because `validatePerasCert` never rejects, an unprivileged NTN peer can:

1. Craft a `PerasCert` for any `PerasRoundNo` pointing to any `Point blk` (including a block on a minority or adversarial fork).
2. Send it via the object-diffusion mini-protocol.
3. The cert is inserted into the ChainDB cert database with the full configured boost weight.
4. Chain selection now treats the attacker-chosen block as boosted, potentially causing the honest node to prefer a non-canonical chain.

This is a **bypass of Peras certificate verification** — the entire cryptographic and committee-membership gate is absent. Impact: **Critical** — unauthorized certificate acceptance that directly manipulates chain selection for any connected peer.

### Likelihood Explanation

Any node that enables the Peras object-diffusion mini-protocol is reachable by any NTN peer without credentials. The attacker needs only a standard network connection and the ability to serialize a `PerasCert` CBOR value (the format is public and simple: a 2-element list of `PerasRoundNo` and `Point blk`). No stake, no keys, no prior relationship required. [7](#0-6) 

### Recommendation

1. **Replace the stub** `validatePerasCert` with a real implementation that verifies committee membership, BLS/aggregate signatures, round validity, and boosted-block plausibility before returning `Right`. The linked issue (`tweag/cardano-peras#120`) tracks this; it must be resolved before the Peras diffusion path is enabled on any network that connects to untrusted peers.

2. **Mirror `processVotes`** in `processCerts`: perform the deduplication check and the `addCert` call inside a single STM transaction (or use a mutex) to close the TOCTOU window between the `alreadyInDb` snapshot and the actual insert.

3. **Gate the mini-protocol** behind a feature flag that is disabled by default until a real `validatePerasCert` is in place, so the stub cannot be reached on production or private-testnet nodes.

### Proof of Concept

1. Connect to a target node as an NTN peer with the Peras object-diffusion mini-protocol enabled.
2. Serialize a `PerasCert` value with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of an adversarial fork block>` using the public CBOR schema:
   ```
   [pcCertRound :: PerasRoundNo, pcCertBoostedBlock :: Point blk]
   ```
3. Send it as an `opwAddObjects` batch via the object-diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=perasWeight params}` unconditionally.
5. `addCert` inserts the cert into the ChainDB.
6. Observe via `ChainDB.getPerasCertIds` that the injected round number is now present, and that chain selection applies the boost to the attacker-specified block.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-182)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```
