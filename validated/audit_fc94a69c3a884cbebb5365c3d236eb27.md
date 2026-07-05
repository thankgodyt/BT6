### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the sole concrete `BlockSupportsPeras` instance unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. This stub is wired directly into the production certificate inbound path (`processCerts` → `makePerasCertPoolWriterFromChainDB`). An unprivileged peer can send a crafted `PerasCert` pointing at any block in the node's VolatileDB; the certificate is accepted, stored, and triggers chain selection with a full Peras weight boost, potentially causing the node to switch to a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must accept or reject inbound Peras certificates before they influence chain selection. The only concrete instance in the codebase — explicitly labelled a "degenerate instance for all blks to get things to compile" — unconditionally returns `Right`:

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

This stub is the function passed to `processCerts` in both production pool-writer constructors:

```haskell
-- makePerasCertPoolWriterFromChainDB (production path)
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`processCerts` calls `validateCert` on every inbound certificate and only rejects a batch when at least one call returns `Left`. Because `validatePerasCert` never returns `Left`, every certificate from every peer passes validation unconditionally.

The accepted certificate is then handed to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event. `chainSelSync` processes this event: if the certificate's `pcCertBoostedBlock` is not already on the current chain but is present in the VolatileDB, it calls `chainSelectionForBlock` for the boosted block. Chain selection then compares the fork containing the boosted block against the current chain using the Peras `WeightedSelectView`, which adds `vpcCertBoost` (the full `perasWeight params` value) to the fork's weight. A fork that would otherwise lose the comparison can win once the illegitimate boost is applied, causing the node to roll back and adopt the attacker-chosen chain.

The asymmetry that mirrors the USDM blocklist report is exact: `validatePerasVote` does perform a real check (voter ID must be in the stake distribution), but `validatePerasCert` — the downstream aggregation step that actually triggers chain selection — performs no check at all. The "source" side (votes) is partially guarded; the "destination" side (the certificate that converts votes into a chain-selection weight boost) is completely unguarded.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A peer with no stake and no cryptographic credentials can:
1. Craft a `PerasCert` whose `pcCertBoostedBlock` points to a block on a competing fork already in the node's VolatileDB.
2. Send it via the Peras object-diffusion mini-protocol.
3. The node accepts it, applies the full `perasWeight` boost to the fork, and may switch away from the canonical chain.

Because the weight boost is additive and applied to every block on the fork after the intersection, even a fork that is several blocks shorter than the current chain can be made to appear heavier. This breaks the chain-selection safety guarantee that honest nodes converge on the same chain.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is active in the production node network stack (code lives in `ouroboros-consensus/src/`, not in test libraries). Any connected peer can send certificate objects. The attack requires only constructing a valid CBOR-encoded `PerasCert` message — no stake, no KES/VRF keys, no committee membership. The TODO comments confirm the gap is known but unresolved.

---

### Recommendation

1. **Immediate mitigation**: Change the default `validatePerasCert` to return `Left PerasValidationErr` (reject all) until real validation is implemented. This is safer than accepting all.
2. **Proper fix**: Implement cryptographic committee-signature verification, quorum-threshold checking, round-number range validation, and boosted-block existence/era checks inside `validatePerasCert` before the Peras object-diffusion protocol is enabled on any network where chain selection integrity matters.
3. **Document the invariant**: Add a note to `processCerts` that the `validateCert` argument is a security boundary and must never be a stub in production.

---

### Proof of Concept

```
1. Attacker connects to a Peras-enabled node via the object-diffusion mini-protocol.

2. Attacker queries the node's VolatileDB (or observes headers via ChainSync) to
   identify a block B on a competing fork F that is slightly shorter than the
   node's current chain C.

3. Attacker sends a PerasCert:
       pcCertRound      = <any fresh round number not yet in the DB>
       pcCertBoostedBlock = blockPoint B

4. processCerts calls validatePerasCert, which returns:
       Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }
   No error is raised.

5. The certificate is stored in PerasCertDB and addPerasCertAsync is called.

6. chainSelSync finds B is in the VolatileDB but not on the current chain.
   It calls chainSelectionForBlock for B.

7. compareChainDiffs now computes weightedSelectView for F, which includes
   vpcCertBoost for B. If this boost exceeds the chain-length deficit of F
   relative to C, preferAnchoredCandidate returns ShouldSwitch.

8. The node rolls back C and adopts F — the attacker-chosen non-canonical chain.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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
