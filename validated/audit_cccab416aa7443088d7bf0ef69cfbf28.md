### Title
Stub `validatePerasCert` Always Accepts Any Peras Certificate, Enabling Unprivileged Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production implementation of `validatePerasCert` is a stub that unconditionally returns `Right` for every inbound `PerasCert`, performing no cryptographic or protocol-level checks. Because Peras certificate weight is the direct input to chain selection (`preferAnchoredCandidate`), any unprivileged peer can inject a crafted certificate that boosts an arbitrary block, causing the honest node to prefer an adversarial fork over the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type-class method `validatePerasCert` is the sole gate between a network-received `PerasCert` and the `PerasWeightSnapshot` that drives chain selection. Its current implementation is:

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

Every certificate, regardless of its content, is accepted and assigned the full configured `perasWeight`. This stub is called directly from the object-diffusion inbound path:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` filters only for duplicate round numbers; it does not re-validate. Any cert that passes the duplicate check is timestamped and forwarded to `addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. The synchronous handler adds the cert to `PerasCertDB`, updates the `PerasWeightSnapshot`, and calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection then calls `preferAnchoredCandidate`, which compares chains by `wsvTotalWeight` — the sum of block number and `weightBoostOfFragment` drawn from the manipulated snapshot: [5](#0-4) 

`wsvTotalWeight` is defined as `PerasWeight (unBlockNo blockNo) <> wsvWeightBoost`, so injected boost weight directly competes with honest chain length: [6](#0-5) 

The `PerasWeightSnapshot` is a shared, globally-mutable map keyed by block point. `addToPerasWeightSnapshot` accumulates weight for any point without any authentication check: [7](#0-6) 

**Analog to the external report:** Just as `NFTMintSale` relied on `nft.totalSupply()` — a shared counter that external minters could inflate — the chain-selection logic here relies on `PerasWeightSnapshot`, a shared weight counter that any external peer can inflate by submitting unauthenticated certificates. The fix in both cases is to use a locally-controlled, properly-validated counter rather than trusting externally-supplied values.

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` that names any block on an adversarial fork as the boosted block. Because `validatePerasCert` always returns `Right`, the certificate is accepted, the adversarial block's weight in `PerasWeightSnapshot` is increased by `perasWeight params`, and chain selection immediately re-evaluates whether to switch to the adversarial fork. If the injected boost exceeds the honest chain's length advantage, the node switches to the adversarial chain. This constitutes a **chain-selection safety failure**: an unprivileged peer causes an honest node to prefer a non-canonical chain, violating the core Peras security guarantee that only legitimately-certified blocks receive weight boosts.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable from any connected peer. No stake, key material, or privileged access is required. The attacker only needs to craft a `PerasCert` with a `pcCertBoostedBlock` pointing to a block on their fork and submit it. The only guard — the duplicate-round-number check — is trivially bypassed by using a fresh `PerasRoundNo`. This is a straightforward, low-effort attack requiring no brute force.

---

### Recommendation

Replace the stub `validatePerasCert` with a complete implementation that verifies:
1. The certificate's cryptographic signature against the known committee public keys for the claimed round.
2. That the claimed `PerasRoundNo` corresponds to a valid, currently-open voting round.
3. That the boosted block point exists on a known chain and is within the valid age window.
4. That the `vpcCertBoost` value is derived from the protocol parameters, not from the certificate itself.

Until full validation is implemented, the `PerasWeightSnapshot` should not be used in production chain selection. The existing `isEmptyPerasWeightSnapshot` fast-path in `preferAnchoredCandidate` (which falls back to length-only comparison) should be the default until the validation stub is replaced. [8](#0-7) 

---

### Proof of Concept

**Setup:** A node with Peras enabled, connected to an adversarial peer. The honest chain has tip at block `H` with block number `N`. The adversarial peer has a fork with tip at block `A` with block number `N - delta` (shorter by `delta` blocks).

**Attack:**
1. Adversarial peer sends a `PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = blockPoint A }` via the Peras certificate object-diffusion protocol.
2. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
3. The cert is added to `PerasCertDB`; `PerasWeightSnapshot` now maps `blockPoint A` → `perasWeight params`.
4. `addPerasCertAsync` triggers `chainSelSync (ChainSelAddPerasCert ...)`.
5. `chainSelectionForBlock` is called for block `A`; `preferAnchoredCandidate` computes:
   - Honest chain total weight: `N + 0` (no boost)
   - Adversarial chain total weight: `(N - delta) + perasWeight params`
6. If `perasWeight params > delta`, the adversarial chain wins and the node switches to it.
7. The adversarial peer can repeat with a new `PerasRoundNo` to accumulate additional weight, overcoming any honest chain length advantage. [1](#0-0) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-203)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-210)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```
