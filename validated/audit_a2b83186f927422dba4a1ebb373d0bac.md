### Title
Unconditional Acceptance of Peer-Supplied Peras Certificates Bypasses Certificate Verification, Enabling Unauthorized Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every inbound `PerasCert`, performing zero cryptographic or protocol validation. Any unprivileged peer can craft and send a `PerasCert` that names an arbitrary block as the boosted target; the certificate is accepted without question, stored in the `PerasCertDB`, and immediately fed into chain selection, where it applies a configurable weight boost (default: 15 block-lengths) to the named block. This can cause an honest node to switch away from the canonical chain to an adversarially chosen fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must authenticate a certificate before it is stored or acted upon. The sole production instance (the universal `StandardHash blk` instance) implements this gate as a stub that always succeeds:

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
``` [1](#0-0) 

This stub is wired directly into the production object-diffusion inbound path via `makePerasCertPoolWriterFromChainDB`:

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    -- TODO replace when actual plumbing is in place
    (validatePerasCert mkPerasParams)
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass (which they always do), forwards each to `addCert` — here `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for synchronous processing by `chainSelSync`, which:
1. Stores the certificate in `PerasCertDB`.
2. Looks up the boosted block in `VolatileDB`.
3. Calls `chainSelectionForBlock` for that block, potentially switching the node's preferred chain. [4](#0-3) 

The `ChainDB.addPerasCertAsync` API entry point is confirmed as the production hook: [5](#0-4) 

The `mkPerasParams` placeholder assigns `perasWeight = PerasWeight 15`, meaning each accepted certificate boosts the named block by the equivalent of 15 block-lengths in chain selection weight: [6](#0-5) 

The missing checks that `validatePerasCert` must eventually perform include (per the Peras design): committee membership proof, cryptographic signature over `(round, boosted-block-point)`, round-number freshness relative to the current slot, and quorum attestation. None of these are present.

The same structural gap exists in `validatePerasVote`, which omits all cryptographic checks and only verifies stake-distribution membership: [7](#0-6) 

---

### Impact Explanation

A Peras certificate's sole purpose is to boost a block's weight in chain selection. Accepting a forged certificate — one naming an adversary-controlled block on a minority fork — causes the receiving node to re-run chain selection for that block with an artificial +15-block weight advantage. If the adversary's fork is within the volatile window (i.e., not yet immutable), the node will switch to it, diverging from the canonical chain. This is a direct chain-selection safety failure triggered by a single unauthenticated network message, matching the "High/Critical — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact category.

---

### Likelihood Explanation

The object-diffusion mini-protocol is a standard node-to-node protocol; any connected peer can send `PerasCert` objects. No stake, key material, or special privilege is required. The attacker only needs to construct a `PerasCert` CBOR value with a `pcCertRound` not already in the database and a `pcCertBoostedBlock` pointing to a block in the target node's volatile window. The `processCerts` deduplication check (filtering by round number already in DB) is the only barrier, and it is trivially bypassed by using a fresh round number.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that enforces:
1. **Committee membership**: the certificate's claimed signers must be elected committee members for the stated round, verified against the ledger's stake distribution.
2. **Cryptographic signature**: the aggregate or threshold signature over `(round, boosted-block-point)` must verify under the committee's keys.
3. **Round freshness**: `pcCertRound` must fall within the acceptable window relative to the current slot (bounded by `perasCertMaxRounds`).
4. **Quorum**: the signing stake must exceed `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.

Until the full implementation is ready, the stub should at minimum **reject all inbound certificates** (return `Left PerasValidationErr` unconditionally) rather than accept them all, so that the network-facing path is safe by default.

The same remediation applies to `validatePerasVote`, which must add signature and committee-membership checks beyond the current stake-lookup.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target node via the node-to-node object-diffusion mini-protocol.
2. Attacker sends a batch containing one `PerasCert`:
   - `pcCertRound = <any round not yet in the target's PerasCertDB>`
   - `pcCertBoostedBlock = <Point of a block on the attacker's minority fork, present in the target's VolatileDB>`
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams` returns `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}` unconditionally. [8](#0-7) 
4. `ChainDB.addPerasCertAsync` enqueues the certificate. [9](#0-8) 
5. `chainSelSync` stores the cert and calls `chainSelectionForBlock` for the boosted block, applying a +15-block weight boost. [10](#0-9) 
6. The target node's chain selection now prefers the adversary's fork over the canonical chain, causing a chain switch.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
