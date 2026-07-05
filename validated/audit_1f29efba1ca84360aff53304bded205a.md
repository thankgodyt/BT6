### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate without performing any cryptographic or structural validation. An unprivileged peer can send a crafted `PerasCert` for any block, causing the receiving node to apply an artificial weight boost to that block during chain selection, potentially making the node prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gating function that must approve a certificate before it is stored and used in chain selection. The sole production instance — `instance StandardHash blk => BlockSupportsPeras blk` — implements this function as an unconditional stub:

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

The comment explicitly acknowledges that validation is incomplete, but unlike the analogous `reveal` function in the external report, no enforcement exists at all — the function returns `Right` for every input.

This stub is wired directly into the production inbound certificate processing path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls this validator on every new inbound certificate and, if it returns `Right`, adds the certificate to the database and triggers chain selection: [3](#0-2) 

Once stored, the certificate is processed by `chainSelSync`, which calls `addPerasCertAsync` and triggers `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection uses `WeightedSelectView`, which adds `wsvWeightBoost` (the sum of all certificate boosts on a fragment) to `wsvBlockNo` to compute `wsvTotalWeight`. A fragment with a higher total weight is preferred: [5](#0-4) 

The default `perasWeight` is `PerasWeight 15`, meaning each accepted certificate adds 15 units of artificial weight to the targeted block's chain fragment: [6](#0-5) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

A peer can craft a `PerasCert` naming any block in the VolatileDB as `pcCertBoostedBlock`. Because `validatePerasCert` never rejects anything, the certificate is stored and the boosted block's chain fragment gains `PerasWeight 15` in the selection comparison. By sending multiple crafted certificates for the same block (each for a distinct `pcCertRound`), an attacker can accumulate enough artificial weight to cause the node to switch away from the honest canonical chain to an adversarially chosen fork. This directly undermines the Peras protocol's chain-selection invariant, which requires that only legitimately quorum-certified blocks receive weight boosts.

---

### Likelihood Explanation

The object diffusion mini-protocol for Peras certificates is reachable by any connected peer without any privilege. The `makePerasCertPoolWriterFromChainDB` writer is the production path used when Peras is enabled. The stub is not guarded by a feature flag at the validation layer — the `TODO` comment and the linked issue (`cardano-peras/issues/120`) confirm the gap is known but not yet closed. Any peer that can connect to the node and send a `PerasCert` message can trigger this path.

---

### Recommendation

Replace the unconditional `Right` stub in `validatePerasCert` with real validation that at minimum verifies:

1. The certificate's aggregate signature over `(electionId, candidate)` is valid against the claimed committee members' keys.
2. The claimed voters collectively hold stake above the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. The `pcCertRound` is within the valid window (not older than `perasCertMaxRounds` from the current round).

Until real validation is implemented, inbound certificates from untrusted peers should be rejected entirely when Peras is enabled, rather than accepted unconditionally.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a Peras-enabled node as a normal peer.
2. Attacker sends a batch containing a crafted `PerasCert { pcCertRound = R, pcCertBoostedBlock = P }` where `P` is the point of a block on an adversarial fork that is currently in the victim's VolatileDB.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }` unconditionally. [7](#0-6) 
5. The cert is added to `PerasCertDB` and `addPerasCertAsync` is called.
6. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block. [8](#0-7) 
7. `weightedSelectView` computes the adversarial fork's total weight as `blockNo + 15`, which may now exceed the honest chain's total weight. [9](#0-8) 
8. The node switches to the adversarial fork.

Repeating step 2 with distinct `pcCertRound` values multiplies the boost by 15 per certificate, allowing the attacker to overcome arbitrarily large honest-chain leads.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
