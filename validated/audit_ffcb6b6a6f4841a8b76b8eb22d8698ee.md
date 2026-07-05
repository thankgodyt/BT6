### Title
Peras Certificate Validation Is a No-Op Stub, Allowing Unprivileged Peers to Inject Arbitrary Chain-Selection Weight Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function — the sole cryptographic gate before a Peras certificate is accepted into the `PerasCertDB` and used to boost chain-selection weight — is a stub that unconditionally returns `Right` for every certificate it receives. Any unprivileged peer can therefore send a crafted certificate boosting an arbitrary block on an adversarial fork, causing the victim node to apply a large weight boost (`perasWeight`, default 15) to that fork and potentially switch away from the honest chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the validation entry point for inbound Peras certificates. The only concrete instance in the production codebase is the degenerate catch-all instance, which performs no cryptographic or semantic checks whatsoever:

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

This stub is called directly in the object-diffusion inbound path for certificates received from peers:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

The `processCerts` function is designed to disconnect from a peer if any certificate fails validation, but since `validatePerasCert` never returns `Left`, this protection is never triggered:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _)            -> throw (PerasCertValidationError errs)
``` [4](#0-3) 

Once accepted, the certificate is stored in `PerasCertDB` via `implAddCert` (which also carries a TODO for non-trivial validation): [5](#0-4) 

The stored certificate immediately contributes to the `PerasWeightSnapshot` returned by `implGetWeightSnapshot`:

```haskell
let weights = mkPerasWeightSnapshot
      [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
      | cert <- Map.elems (pcdsCertsByTicket pcds) ]
``` [6](#0-5) 

Chain selection then uses this snapshot via `weightedSelectView` → `weightBoostOfFragment` → `wsvTotalWeight` to compare candidate fragments: [7](#0-6) 

When `addPerasCertAsync` is called (triggered by the inbound cert), `chainSelSync` processes the cert and calls `chainSelectionForBlock` for the boosted block, potentially switching the node to the adversarially-boosted fork: [8](#0-7) 

The rollback depth is governed by `takeVolatileSuffix`, which interprets `k` as a weight. With `perasWeight = 15`, a single fraudulent certificate can make a fork appear to have 15 additional units of weight, potentially overcoming an honest chain that is up to 15 blocks longer: [9](#0-8) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An adversary controlling a single peer connection can:
1. Craft a `PerasCert` claiming to boost a block on an adversarial fork.
2. Send it via the Peras certificate object-diffusion mini-protocol.
3. The victim node accepts it without any cryptographic check, stores it in `PerasCertDB`, and triggers chain selection.
4. The adversarial fork gains `perasWeight` (default 15) extra weight units.
5. If the adversarial fork is within 15 weight units of the honest chain, the victim node switches to it — accepting an invalid or adversarially-controlled chain.

This directly undermines the Peras security guarantee that weight boosts are only granted to blocks certified by a quorum of honest stake holders.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol for Peras certificates is reachable from any peer connection. No stake, key material, or privileged access is required. The attacker only needs to construct a `PerasCert` with a valid CBOR encoding (round number + block point), which is trivially achievable. The stub is the only instance in the production codebase and is used in both the `PerasCertDB`-direct path and the `ChainDB` path. The TODO comment at issue #120 confirms this is a known gap, not an intentional design choice.

---

### Recommendation

Replace the stub `validatePerasCert` instance with a real implementation that verifies:
1. The aggregate BLS signature over the round number and boosted block hash (using the concrete `V1.PerasCert` type already defined in `Ouroboros.Consensus.Peras.Cert.V1`).
2. That the signers form a valid committee for the claimed round (VRF-based eligibility proofs via `PerasVoteEligibilityProof`).
3. That the total stake of the signers exceeds the quorum threshold (`stakeAboveThreshold`).

Until this is implemented, the Peras weight boost mechanism must not be enabled in any environment reachable by untrusted peers.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node with Peras enabled (`eraPerasRoundLength` set in `EraParams`).
2. From a peer connection, send a `PerasCert` message via the object-diffusion protocol targeting a block on a minority fork `F` (e.g., a fork 10 blocks behind the honest tip).
3. The cert passes `validatePerasCert` unconditionally and is stored in `PerasCertDB`.
4. `addPerasCertAsync` triggers `chainSelSync`, which calls `chainSelectionForBlock` for the boosted block on `F`.
5. `weightedSelectView` computes `wsvTotalWeight` for `F`'s fragment: its block number plus `perasWeight = 15`.
6. If the honest chain's tip block number minus `F`'s fork point is ≤ 15, `preferCandidate` returns `ShouldSwitch` and the node adopts `F`.
7. The node has been diverted to the adversarial fork by a single unauthenticated network message.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-127)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L369-377)
```haskell
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```
