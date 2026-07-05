### Title
Stub `validatePerasCert` Unconditionally Returns Success, Enabling Unprivileged Peers to Manipulate Peras Chain-Weight Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural checks. This stub is wired directly into the production ObjectDiffusion inbound path. An unprivileged peer can send crafted Peras certificates that boost arbitrary blocks in the node's VolatileDB, inflating their chain weight and potentially causing the node to switch away from the honest chain.

---

### Finding Description

**Root cause — always-succeeding validation stub**

`validatePerasCert` in the degenerate `instance StandardHash blk => BlockSupportsPeras blk` unconditionally returns `Right`:

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

This is the only instance available for all `StandardHash blk` types and is therefore the instance used in production.

**Production call site — ObjectDiffusion inbound writer**

`makePerasCertPoolWriterFromChainDB` passes this stub directly as the validator for all inbound certificates received from peers:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` accepts every certificate whose `validateCert` call returns `Right` — which is every certificate, unconditionally: [3](#0-2) 

**Downstream chain-selection impact**

Once accepted, the certificate is added to `PerasCertDB` via `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it:

1. Checks the boosted block is not older than the immutable tip (slot check only).
2. Looks up the boosted block in the VolatileDB — if present, proceeds.
3. Calls `chainSelectionForBlock` for the boosted block. [4](#0-3) 

The accepted certificate is also included in `implGetWeightSnapshot`, which feeds `weightBoostOfFragment`: [5](#0-4) 

`weightBoostOfPoint` returns `mempty` (zero) for unknown points and the stored `PerasWeight` for known ones — so a crafted certificate for a block that is in the VolatileDB immediately inflates that block's chain weight: [6](#0-5) 

`compareAnchoredFragments` uses this weight snapshot for all chain comparisons when Peras is active: [7](#0-6) 

**Analog to the StaticHyVM pattern**

Just as `StaticHyVM.doDelegateCall` calls `delegatecall` without checking whether the target contract exists — causing the call to silently succeed and return empty data — `validatePerasCert` calls nothing and silently returns `Right` for every input. Both patterns share the same root cause: a call that is supposed to perform a meaningful check instead always reports success, causing downstream logic to proceed as if the check passed.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` naming any block hash that is present in the target node's VolatileDB. Because validation always succeeds, the certificate is stored and the named block receives a `PerasWeight` boost equal to `perasWeight mkPerasParams`. If the attacker's fork contains that block and the boosted weight tips the `wsvTotalWeight` comparison in `preferCandidate`, the node switches to the attacker's fork even if it is shorter than the honest chain.

This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of the Ouroboros protocol. [8](#0-7) 

---

### Likelihood Explanation

- The ObjectDiffusion mini-protocol for Peras certificates is present and active in the production codebase; any connected peer can send `PerasCert` objects.
- No privileged access, stake, VRF/KES keys, or cryptographic break is required.
- The only precondition is that the target block exists in the node's VolatileDB, which is trivially satisfied by first delivering the block via the normal BlockFetch protocol.
- The `validatePerasCert` stub is explicitly marked TODO with a linked issue, confirming it is not a deliberate design choice but an incomplete implementation shipped in production code. [9](#0-8) 

---

### Recommendation

Before the Peras ObjectDiffusion mini-protocol is exposed to untrusted peers, `validatePerasCert` must perform real validation, including at minimum:

1. Cryptographic signature verification over the certificate fields.
2. Verification that the boosted block point is a valid, known block on a plausible chain.
3. Verification that the certificate's round number is within the valid Peras round window.
4. Committee membership and quorum checks for the signers.

Until a real implementation is in place, the inbound ObjectDiffusion writer for Peras certificates should either be disabled or restricted to trusted peers only.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the standard node-to-node protocol.
2. Deliver a valid block `B` on an adversarial fork via BlockFetch so that `B` is stored in the node's VolatileDB.
3. Construct a `PerasCert { pcCertRound = r, pcCertBoostedBlock = blockPoint B }` for any round `r` not already in the `PerasCertDB`.
4. Send the certificate via the ObjectDiffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
6. The certificate is added to `PerasCertDB`; `implGetWeightSnapshot` now includes `(blockPoint B, perasWeight mkPerasParams)`.
7. `chainSelSync` triggers `chainSelectionForBlock` for `B`; `weightBoostOfFragment` assigns the extra weight to any fragment containing `B`.
8. If the adversarial fork containing `B` now has `wsvTotalWeight` greater than the honest chain, `preferCandidate` returns `ShouldSwitch` and the node adopts the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L208-213)
```haskell
weightBoostOfPoint ::
  forall blk.
  StandardHash blk =>
  PerasWeightSnapshot blk -> Point blk -> PerasWeight
weightBoostOfPoint (PerasWeightSnapshot weightByPoint) pt =
  Map.findWithDefault mempty pt weightByPoint
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L114-117)
```haskell
compareAnchoredFragments cfg weights frag1 frag2
  -- Optimize the case where Peras is disabled.
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition frag1 frag2) $
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
