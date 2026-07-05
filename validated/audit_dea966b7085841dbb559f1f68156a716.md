### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Artificial Chain-Weight Inflation via Crafted Peras Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The production certificate-ingestion path calls `validatePerasCert mkPerasParams` as its sole validation gate for inbound Peras certificates. The concrete implementation of `validatePerasCert` that is wired in is a deliberate stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic, quorum, or committee-membership checks. An unprivileged peer can therefore send a crafted `PerasCert` pointing to any block, have it accepted without rejection, and cause the receiving node to re-run chain selection with that block artificially boosted by `PerasWeight 15`. If the adversarial chain's total weight (block count + boost) exceeds the honest chain's weight, the node switches forks.

---

### Finding Description

**Stub validation in the `BlockSupportsPeras` degenerate instance**

The `BlockSupportsPeras` type class declares `validatePerasCert` as the method responsible for verifying that a received certificate is legitimate before it is stored and acted upon. The only concrete instance in the codebase is a catch-all "degenerate instance for all blks to get things to compile":

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

This function accepts every certificate unconditionally and assigns it the full configured boost weight (`PerasWeight 15` from `mkPerasParams`). [2](#0-1) 

**Stub wired into both production pool-writer paths**

Both `makePerasCertPoolWriterFromCertDB` (used in isolated tests) and `makePerasCertPoolWriterFromChainDB` (the production path that feeds the `ChainDB`) pass this stub as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) [4](#0-3) 

**`processCerts` relies entirely on `validateCert` as its only guard**

`processCerts` filters out already-known rounds, then calls `validateCert` on every remaining certificate. Because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is stored:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [5](#0-4) 

**Accepted certificate triggers chain selection with inflated weight**

Once stored, `chainSelSync` is invoked for the boosted block. Chain selection uses `preferAnchoredCandidate` / `compareAnchoredFragments`, which computes `weightedSelectView` — the sum of block count and `weightBoostOfFragment`. The fraudulent certificate contributes `PerasWeight 15` to the adversarial fragment's total weight:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [6](#0-5) 

The chain-selection comparison then prefers the candidate if its total weight exceeds the current chain's:

```haskell
case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
  LT -> ShouldSwitch (Heavier $ ...)
``` [7](#0-6) 

The full chain-selection trigger path in `chainSelSync`: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` whose `pcCertBoostedBlock` points to any block in the node's VolatileDB (e.g., the tip of an adversarial fork). The certificate passes "validation" (a no-op), is stored in `PerasCertDB`, and causes the node to re-evaluate chain selection with the adversarial fork receiving `+15` weight. A fork that is up to 15 blocks shorter than the honest chain will be preferred after a single crafted certificate. An adversary controlling a peer connection can therefore force an honest node to switch to a non-canonical chain without holding any stake or forging any valid blocks, violating the chain-selection security assumption of Ouroboros Peras.

This matches the allowed impact: **"Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."**

---

### Likelihood Explanation

The attack requires only a peer connection and knowledge of a block hash present in the target node's VolatileDB (obtainable via the ChainSync miniprotocol). No stake, no keys, no cryptographic material are needed. The `PerasCert` wire format is serialised/deserialised via `Serialise` instances and accepted by the `ObjectDiffusion` layer from any connected peer. The vulnerability is present in the current codebase whenever Peras is enabled.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the claimed committee members' public keys.
2. That the claimed voters collectively hold stake above the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. That the certificate's round number and boosted block are within the valid window.

Until the real implementation is ready, the `processCerts` inbound path should reject all certificates (or the Peras feature flag should gate the entire ingestion path) so that the stub cannot be exploited over the network.

---

### Proof of Concept

The following sequence demonstrates the issue on a private testnet or simulation with Peras enabled:

1. Node A has an honest chain of length N and a fork block F at length N-14 in its VolatileDB (obtained by any peer via ChainSync).
2. Adversarial peer B constructs a `PerasCert` with `pcCertBoostedBlock = blockPoint F` and any `pcCertRound`.
3. B sends the certificate to A via the Peras certificate diffusion miniprotocol (`ObjectDiffusion`).
4. A's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally. [9](#0-8) 
5. The certificate is stored in `PerasCertDB`.
6. `chainSelSync` triggers chain selection for F; the fork's total weight becomes `(N-14) + 15 = N+1`, exceeding the honest chain's weight of N. [10](#0-9) 
7. Node A switches to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
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
