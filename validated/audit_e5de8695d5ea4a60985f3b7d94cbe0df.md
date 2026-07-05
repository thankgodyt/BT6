### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation for the `BlockSupportsPeras` class unconditionally accepts every inbound Peras certificate without performing any cryptographic or semantic checks. An unprivileged peer can send a crafted certificate boosting any block in the VolatileDB, causing the receiving node to assign artificial weight to an adversarial chain fragment and potentially switch away from the honest canonical chain.

---

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate validation. Its only production instance (the `StandardHash blk` catch-all instance) implements `validatePerasCert` as an unconditional stub:

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

The `PerasValidationErr` type for this instance is a single no-field constructor — it cannot even express a meaningful rejection reason:

```haskell
data PerasValidationErr blk
  = PerasValidationErr
  deriving stock (Show, Eq)
``` [2](#0-1) 

This stub is wired directly into the production inbound certificate processing path. `makePerasCertPoolWriterFromChainDB` — the writer used for the live ChainDB — passes `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` calls this validator on every inbound certificate batch received from a peer. Because `validatePerasCert` always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

`chainSelSync` then processes the accepted certificate. It only checks whether the boosted block's slot is older than the immutable tip (trivially avoidable by targeting a recent block) and whether the boosted block is present in the VolatileDB. If both conditions are met, it triggers `chainSelectionForBlock` for the boosted block: [5](#0-4) 

Chain selection uses `WeightedSelectView`, which computes `wsvTotalWeight = blockNo + wsvWeightBoost`. The weight boost contributed by the fake certificate (`perasWeight params`) is added to the boosted block's chain fragment, potentially making a shorter adversarial fork appear heavier than the honest chain: [6](#0-5) 

---

### Impact Explanation

**Impact: High — Chain selection manipulation by an unprivileged peer.**

An attacker who can send Peras certificate messages to a node (via the object diffusion miniprotocol, which is an unauthenticated peer-to-peer channel) can craft a certificate referencing any block hash and slot in the VolatileDB. Because `validatePerasCert` performs zero checks, the certificate is accepted, stored in the `PerasCertDB`, and its weight boost is applied to the target block's chain fragment via `PerasWeightSnapshot`. If the configured `perasWeight` is large enough relative to the honest chain's length advantage, the node will switch to the adversarial fork. This directly violates the chain selection security invariant: an honest node should only prefer a chain that is genuinely heavier under the protocol rules, not one artificially inflated by unauthenticated certificates.

---

### Likelihood Explanation

**Likelihood: High (when Peras is enabled).**

The attack requires only the ability to send a well-formed CBOR-encoded `PerasCert` message over the object diffusion miniprotocol — no keys, no stake, no privileged access. The `PerasCert` structure contains only a round number and a block point (slot + hash), both of which are observable from the public chain. The attacker needs to know a block hash present in the target node's VolatileDB, which is obtainable via ChainSync. The CHANGELOG explicitly notes that Peras is an opt-in feature flag; however, the stub validation is the only production implementation and will be active for any node that enables Peras (including private testnets and future mainnet deployments).

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The aggregate BLS signature over the certificate's round number and boosted block hash against the committee's public keys (as defined in `Ouroboros.Consensus.Peras.Cert.V1`).
2. That the voters listed in the certificate were eligible committee members for the claimed round (committee membership check).
3. That the quorum threshold is met by the signers' combined stake.
4. That the certificate's round number is within the valid range relative to the current slot.

Until real validation is implemented, the object diffusion handler should reject all inbound certificates (return a hard error) rather than accept them unconditionally, so that enabling Peras does not silently open this attack surface.

---

### Proof of Concept

**Setup:** Node A has Peras enabled. Its VolatileDB contains block `B_adv` at slot `S` on a minority fork (e.g., one block shorter than the honest tip). The honest chain has tip at block number `N`.

**Attack:**
1. Attacker connects to Node A as an unprivileged peer via the object diffusion miniprotocol.
2. Attacker sends a `PerasCert` with:
   - `pcCertRound` = any valid round number (e.g., current round)
   - `pcCertBoostedBlock` = `BlockPoint S (hash of B_adv)`
3. `processCerts` calls `validatePerasCert mkPerasParams` → returns `Right` unconditionally.
4. The cert is stored in `PerasCertDB`; `chainSelSync` is triggered.
5. `pointSlot boostedBlock >= AF.anchorToSlotNo immTip` → not too old, passes.
6. `VolatileDB.getBlockComponent cdbVolatileDB GetHeader (hash of B_adv)` → returns `Just boostedHdr`.
7. `chainSelectionForBlock` is called for `B_adv`.
8. `weightedSelectView` computes `wsvTotalWeight` for the adversarial fragment as `(N-1) + perasWeight`, which exceeds the honest chain's `N + 0` if `perasWeight >= 2`.
9. Node A switches to the adversarial fork. [1](#0-0) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-342)
```haskell
  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)
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
