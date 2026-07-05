Let me analyze the vulnerability class from the external report and search for analogous issues in the Ouroboros Consensus codebase.

The external report's vulnerability class is: **an extra/incorrect guard condition that gates a mandatory validation check, causing the check to be skipped when it should always run** — leading to invalid inputs being accepted or valid inputs being rejected.

Let me search for analogous patterns in the consensus codebase.

### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates Without Any Cryptographic or Quorum Checks — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance — which is the **only** instance in the codebase and is used in all production code paths — implements `validatePerasCert` as an unconditional `Right`, performing zero validation. Every Peras certificate received from any unprivileged peer is accepted and stored in the `PerasCertDB`, where it immediately influences chain selection by adding artificial weight to any block the attacker designates. This is the direct analog of the ERC-721 finding: a mandatory check (certificate signature/quorum verification) is absent, causing invalid inputs to be accepted when they should be rejected.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub in production:** [1](#0-0) 

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

This is not a test helper. It is the sole `instance StandardHash blk => BlockSupportsPeras blk` — the universal instance used for all block types. [2](#0-1) 

**Production inbound path — `processCerts` calls this stub validator:**

`makePerasCertPoolWriterFromChainDB` (the production writer used by the node) passes `validatePerasCert mkPerasParams` directly as the validation function: [3](#0-2) 

`processCerts` then filters out already-known rounds and calls `validateCert` on the remainder. Because `validatePerasCert` always returns `Right`, every new-round certificate passes: [4](#0-3) 

**Chain selection impact — accepted certificates directly alter the weight snapshot:**

`chainSelSync` receives the accepted `ValidatedPerasCert` and adds it to `PerasCertDB`. The `PerasWeightSnapshot` is built from all stored certs and is used by `preferAnchoredCandidate` to compare chain fragments: [5](#0-4) 

`preferAnchoredCandidate` uses the weight snapshot to compute `weightedSelectView` for each candidate, and a chain boosted by a fake certificate can exceed the honest chain's total weight: [6](#0-5) 

**Analog to the ERC-721 finding:**

| ERC-721 | Ouroboros Consensus |
|---|---|
| `onERC721Received` must always be called on contract recipients | `validatePerasCert` must always verify certificate signatures and quorum |
| Extra ERC-165 guard causes the mandatory call to be skipped | Stub implementation causes the mandatory check to be entirely absent |
| Valid receivers cannot receive tokens | Invalid certificates are accepted and influence chain selection |

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block hash. Because `validatePerasCert` performs no signature verification, no quorum check, and no committee membership check, the certificate is accepted and stored. The `PerasWeightSnapshot` is updated, and `chainSelSync` triggers chain selection for the boosted block. If the attacker's designated block is on a competing fork, the honest node may compute that fork as having higher total weight (`wsvTotalWeight = blockNo + weightBoost`) and switch to it, abandoning the canonical chain.

This matches the **Critical** impact class: bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain selection manipulation.

### Likelihood Explanation

Any peer connected via the object diffusion miniprotocol can send `PerasCert` objects. The `opwAddObjects` handler in `makePerasCertPoolWriterFromChainDB` is invoked for every inbound batch. No stake, key material, or privileged access is required. The only precondition is that Peras is enabled on the target node (non-default but explicitly supported configuration). The attack requires sending a single well-formed CBOR-encoded `PerasCert` with a chosen `pcCertBoostedBlock`.

### Recommendation

Replace the stub `validatePerasCert` implementation with actual cryptographic and quorum validation before Peras is enabled in any production deployment. At minimum, the function must verify:
1. The aggregate vote signature over the certificate's `(electionId, candidate)` pair.
2. That the signers constitute a valid quorum (total stake ≥ threshold + safety margin).
3. That each signer was an eligible committee member for the claimed round.

Until real validation is implemented, the object diffusion inbound handler should refuse all inbound certificates (return a hard error rather than silently accepting them) when the validation function is known to be a stub.

### Proof of Concept

1. Connect to a Peras-enabled node as an unprivileged peer via the object diffusion miniprotocol.
2. Send a `PerasCert` with `pcCertRound = R` (any round not yet in the DB) and `pcCertBoostedBlock = BlockPoint s h` where `h` is the hash of a block on a competing fork.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
4. The cert is stored in `PerasCertDB` via `addCert`.
5. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. `constructPreferableCandidates` computes `weightedSelectView` using the updated `PerasWeightSnapshot`; the competing fork now has `blockNo + 15` total weight.
7. If this exceeds the honest chain's total weight, the node switches to the adversarial fork. [7](#0-6) [4](#0-3) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
