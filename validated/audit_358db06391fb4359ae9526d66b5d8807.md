### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or committee-membership checks. Any unprivileged peer can send a crafted `PerasCert` over the Peras certificate mini-protocol; it will pass "validation," be persisted to the `PerasCertDB`, and trigger chain selection with an artificial weight boost of `perasWeight` (15 by default) applied to an attacker-chosen block. This is the direct analog of the EnsoWallet EXECUTOR issue: a privileged operation (certificate acceptance → chain-weight mutation) is reachable through an indirect path (the stub validator) with no access control.

---

### Finding Description

**Root cause — unconditional `Right` in the degenerate `BlockSupportsPeras` instance:** [1](#0-0) 

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

This is the **only** instance of `BlockSupportsPeras` in the codebase (declared as a catch-all `instance StandardHash blk => BlockSupportsPeras blk`): [2](#0-1) 

No committee membership, no quorum proof, no cryptographic signature, no round-number plausibility check is performed. The function wraps the raw peer-supplied `PerasCert` directly into a `ValidatedPerasCert` and assigns it the full protocol boost weight.

**Inbound path — production pool writer uses this stub:** [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` — the production writer used for peer-received certificates — passes `(validatePerasCert mkPerasParams)` as the validation function to `processCerts`. Because `validatePerasCert` always returns `Right`, `processCerts` always reaches the `([], validatedCerts)` branch and calls `addCert` for every peer-supplied certificate: [4](#0-3) 

**Chain selection impact — accepted cert triggers weight-boosted chain selection:**

Once the cert is enqueued via `ChainDB.addPerasCertAsync`, `chainSelSync` processes it: [5](#0-4) 

If the attacker-chosen `pcCertBoostedBlock` is present in the `VolatileDB`, `chainSelectionForBlock` is called for that block. The weight snapshot now includes the artificial boost, and `preferAnchoredCandidate` uses `wsvTotalWeight` (block count + boost) to decide whether to switch chains: [6](#0-5) 

A boost of 15 (`perasWeight` default) is equivalent to 15 extra blocks of chain weight, sufficient to make a minority fork preferred over the honest chain.

---

### Impact Explanation

**Severity: High — Chain selection manipulation by an unprivileged peer.**

An attacker with no keys or stake can:
1. Craft a `PerasCert{pcCertRound = r, pcCertBoostedBlock = adversarialBlockPoint}` for any block hash present in the target node's `VolatileDB`.
2. Send it over the Peras certificate mini-protocol.
3. The node accepts it unconditionally, stores it, and re-runs chain selection with the adversarial block receiving a weight boost of 15.
4. If the adversarial fork is within 15 blocks of the honest tip, the node switches to it.

This satisfies the **High** impact category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

Additionally, because `pcCertBoostedBlock` is fully attacker-controlled, the attacker can target any block in the volatile window, including blocks on a double-spend fork.

---

### Likelihood Explanation

**Realistic and low-effort.** The attacker needs only:
- Network connectivity to the target node (standard peer connection).
- Knowledge of a block hash in the target's VolatileDB (obtainable via the ChainSync mini-protocol, which is public).
- The ability to serialize a `PerasCert` (two CBOR fields: a `Word64` round number and a block `Point`).

No keys, no stake, no privileged access required. The stub is the **only** `BlockSupportsPeras` instance in the codebase and is used in the production `makePerasCertPoolWriterFromChainDB` path. The `TODO` comment at line 350 and the linked issue (`cardano-peras/issues/120`) confirm this is a known incomplete implementation shipped in the current codebase state.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. **Committee membership**: the certificate's claimed signers are elected committee members for the given round (VRF-based sortition check).
2. **Quorum**: the aggregate stake of signers meets `perasQuorumStakeThreshold`.
3. **Cryptographic signatures**: each signer's KES/BLS signature over the certificate body is valid.
4. **Round plausibility**: `pcCertRound` falls within the current or recent rounds (reject stale/future rounds).

Until the real implementation is in place, the inbound certificate handler should reject all certificates at the network boundary (return `Left PerasValidationErr` unconditionally) rather than accept them all. This matches the principle from the EnsoWallet report: implement an explicit allowlist (here: cryptographic proof of committee authority) rather than allowing unrestricted write access to sensitive state.

---

### Proof of Concept

**Setup:** A Cardano node with Peras enabled, connected to an attacker-controlled peer.

**Steps:**

1. Attacker connects to the target node and learns block hash `H` of a block on a minority fork via ChainSync.
2. Attacker constructs a CBOR-encoded `PerasCert`:
   ```
   [roundNo :: Word64, boostedBlock :: Point]  -- e.g., [42, (slotNo, H)]
   ```
3. Attacker sends this cert via the Peras certificate ObjectDiffusion mini-protocol.
4. Target node calls `processCerts` → `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert {vpcCert = cert, vpcCertBoost = PerasWeight 15})`.
5. Cert is stored in `PerasCertDB`; `chainSelSync` is triggered for block `H`.
6. `constructPreferableCandidates` now sees the fork containing `H` with weight `blockNo(H) + 15`; if this exceeds the honest chain's weight, the node switches forks.

**Expected (correct) behavior:** Step 4 should return `Left PerasValidationErr` because the cert carries no valid committee proof.

**Actual behavior:** Step 4 returns `Right`, the cert is accepted, and chain selection is re-run with the artificial boost applied. [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
