### Title
Peras Certificate Verification Bypass: `validatePerasCert` Unconditionally Returns Success, Allowing Unauthorized Chain-Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — which is the **only** production instance for all block types — implements `validatePerasCert` as an unconditional `Right`, meaning every inbound Peras certificate is accepted as cryptographically valid regardless of its actual content. The object-diffusion inbound path calls this stub directly, so an unprivileged peer can inject certificates that boost arbitrary blocks and trigger chain selection for a non-canonical chain.

---

### Finding Description

**Root cause — stub validation always returns success:**

In the degenerate `instance StandardHash blk => BlockSupportsPeras blk` (the only instance in the codebase), `validatePerasCert` is:

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

No signature, committee membership, round-number range, or boosted-block existence check is performed. The function signature promises `Either (PerasValidationErr blk) (ValidatedPerasCert blk)` but the `Left` branch is structurally unreachable.

**Inbound network path — stub is wired directly into production:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [2](#0-1) 

`processCerts` applies `validateCert` to every inbound certificate and, because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken — every certificate is forwarded to `addCert`: [3](#0-2) 

**Chain-selection consequence:**

`addPerasCertAsync` enqueues the certificate into the `ChainSelQueue`. `chainSelSync` then processes it: if the boosted block is in the VolatileDB, it calls `chainSelectionForBlock` for that block, potentially switching the node to a fork whose weight has been artificially inflated by the fraudulent certificate's `vpcCertBoost = perasWeight params` (currently `PerasWeight 15`): [4](#0-3) 

---

### Impact Explanation

**High — chain selection manipulation via unauthorized Peras certificate acceptance.**

A crafted certificate carries two attacker-controlled fields: `pcCertRound` (any round number) and `pcCertBoostedBlock` (any block point). Because `validatePerasCert` never rejects, the attacker can:

1. Boost any block already present in the target node's VolatileDB, causing `chainSelectionForBlock` to re-evaluate that fork with an extra `PerasWeight 15` boost.
2. Cause the honest node to prefer a non-canonical, adversarially-chosen chain over the canonical one, violating the Peras chain-selection invariant that only legitimately certified blocks receive weight boosts.

This matches the **High** impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

**High.** The attack requires only:
- Network connectivity to a node running the Peras object-diffusion mini-protocol.
- The ability to send a well-formed (but cryptographically fraudulent) `PerasCert` message — a trivially constructable two-field record (`pcCertRound`, `pcCertBoostedBlock`).
- Knowledge of a block hash present in the target's VolatileDB (obtainable via ChainSync).

No keys, stake, or privileged access are required. The stub is explicitly marked TODO and is wired into the production `makePerasCertPoolWriterFromChainDB` path, not gated behind a feature flag.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate committee signature over `(electionId, candidate)` using the registered voter verification keys.
2. That the signers collectively hold stake above `perasQuorumStakeThreshold`.
3. That `pcCertRound` falls within the valid window relative to the current chain tip.
4. That `pcCertBoostedBlock` refers to a block that satisfies the `perasBlockMinSlots` age requirement.

Until the real implementation is ready, the stub should be gated behind a compile-time or runtime feature flag so that the object-diffusion writer for Peras certificates is not reachable on production nodes.

---

### Proof of Concept

**Setup:** A private testnet with one honest node (`N`) running the Peras object-diffusion mini-protocol, and one attacker node (`A`).

1. `A` connects to `N` via the object-diffusion mini-protocol for Peras certificates.
2. `A` observes `N`'s VolatileDB via ChainSync to learn the hash `H` of a block on a minority fork `F` that is currently not preferred by `N`.
3. `A` constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s H }` for any round `r` not yet in `N`'s PerasCertDB.
4. `A` sends this certificate to `N` via the object-diffusion protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
6. The certificate is forwarded to `ChainDB.addPerasCertAsync`.
7. `chainSelSync` finds block `H` in the VolatileDB and calls `chainSelectionForBlock` for fork `F`, now weighted `+15` above its natural length.
8. If fork `F`'s boosted weight exceeds `N`'s current chain weight, `N` switches to `F` — a non-canonical chain chosen by the attacker.

**Expected result without fix:** `N` switches to the adversarially-boosted fork.
**Expected result with fix:** The certificate is rejected at step 5 with a `Left (InvalidCertSignature ...)` error, `N` disconnects from `A`, and no chain switch occurs.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-133)
```haskell
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
