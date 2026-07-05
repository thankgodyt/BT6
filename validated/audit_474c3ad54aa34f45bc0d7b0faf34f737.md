### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Arbitrary Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every inbound Peras certificate, performing zero cryptographic verification. Because this function is wired directly into the live `makePerasCertPoolWriterFromChainDB` path, any unprivileged peer can inject arbitrary Peras certificates over the object-diffusion mini-protocol. Each accepted certificate adds a configurable weight boost (`perasWeight = 15` by default) to an attacker-chosen block point in the `PerasWeightSnapshot`, which is then consumed by chain selection's `WeightedSelectView`. This lets an adversary make an honest node prefer a non-canonical chain without possessing any stake, keys, or quorum.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

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

This is the **only** instance of `BlockSupportsPeras` in the production codebase — it is a catch-all `instance StandardHash blk => BlockSupportsPeras blk`. It accepts every certificate unconditionally and assigns it the full configured boost weight.

**Wiring into the live inbound path:**

Both production pool-writer constructors pass this stub as the validation callback: [2](#0-1) 

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← stub, always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
```

**`processCerts` accepts the batch when all certs pass:** [3](#0-2) 

Because `validatePerasCert` never returns `Left`, `partitionEithers` always yields an empty error list, so every certificate in every batch is forwarded to `addPerasCertAsync`.

**`addPerasCertAsync` triggers chain selection:** [4](#0-3) 

`chainSelSync` stores the certificate in `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block, which re-evaluates chain selection with the new weight.

**Chain selection consumes the injected weight:** [5](#0-4) 

`wsvTotalWeight` = `BlockNo` + `wsvWeightBoost`. The `wsvWeightBoost` is computed by `weightBoostOfFragment` over the `PerasWeightSnapshot`, which now contains the attacker-injected entry. A chain whose tip has accumulated enough injected boost can exceed the honest chain's total weight and be selected.

**The boost magnitude is significant:** [6](#0-5) 

`perasWeight = PerasWeight 15`. Each injected certificate adds 15 weight units to the target block. Since `wsvTotalWeight` is compared directly against the honest chain's block-number-based weight, an adversary sending `N` certificates for the same block point accumulates `15 * N` extra weight, which can overcome an honest chain lead of up to `15 * N` blocks.

---

### Impact Explanation

An unprivileged peer can cause an honest node to switch its current selection to a non-canonical chain by:

1. Sending crafted `PerasCert` objects (one per Peras round number, since the DB deduplicates by round) targeting a block on an adversarial fork.
2. Each certificate is accepted without any BLS signature, committee membership, VRF, or quorum check.
3. The accumulated weight boost on the adversarial fork's tip can exceed the honest chain's total weight.
4. Chain selection switches to the adversarial fork.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of Peras/Praos.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a live, reachable network endpoint. Any peer that connects to the node can send `PerasCert` messages. No stake, keys, or prior authentication is required. The only deduplication guard is the round number, which an attacker can trivially vary across rounds. The vulnerability is exploitable by a single malicious peer with a standard network connection.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:

1. **BLS aggregate signature** over `(roundNo, boostedBlock)` using the aggregate public key of the claimed voters (as already defined in `Ouroboros.Consensus.Peras.Cert.V1` and `Ouroboros.Consensus.Peras.Crypto.BLS`).
2. **Committee membership and VRF eligibility** for each claimed voter seat.
3. **Quorum threshold**: total stake of verified voters must exceed `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. **Round validity**: the certificate's round number must be within the acceptable window relative to the current chain tip.

Until real validation is in place, inbound certificates from untrusted peers should be rejected entirely rather than accepted unconditionally.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → ObjectDiffusion mini-protocol
     → makePerasCertPoolWriterFromChainDB.opwAddObjects
     → processCerts [...] (validatePerasCert mkPerasParams) [...]
     → validatePerasCert: always returns Right (no crypto check)
     → addPerasCertAsync chainDB cert
     → chainSelSync (ChainSelAddPerasCert cert)
     → PerasCertDB.addCert  (stores cert)
     → chainSelectionForBlock (re-runs chain sel for boosted block)
     → weightedSelectView uses PerasWeightSnapshot
     → wsvTotalWeight(adversarial fork) > wsvTotalWeight(honest chain)
     → node switches to adversarial fork
```

**Concrete exploit sketch:**

```haskell
-- Attacker constructs a cert for a block on their fork at round R
let craftedCert = PerasCert
      { pcCertRound      = PerasRoundNo R
      , pcCertBoostedBlock = adversarialBlockPoint  -- attacker's fork tip
      }
-- Send via object diffusion; validatePerasCert accepts it unconditionally
-- Repeat for rounds R+1, R+2, ... to accumulate weight 15*N
-- Once 15*N > (honest chain length - adversarial chain length),
-- the node's chain selection switches to the adversarial fork
```

The only per-round deduplication means the attacker needs `ceil(lead / 15)` distinct round numbers, all of which are freely chosen.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
