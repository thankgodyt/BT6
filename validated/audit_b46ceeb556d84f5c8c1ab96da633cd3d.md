### Title
Peras Certificate Validation Bypass Allows Arbitrary Chain-Weight Boost via Crafted Peer Certificate — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the `BlockSupportsPeras` default instance unconditionally returns `Right` (success) for every inbound certificate, performing no cryptographic or semantic checks. Because the object-diffusion inbound path calls this function directly on peer-supplied certificates, any unprivileged peer can inject a certificate that boosts an arbitrary block's weight in chain selection, potentially causing an honest node to prefer a non-canonical adversarial chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub**

The `BlockSupportsPeras` class defines `validatePerasCert` as the function that must verify a `PerasCert` before it is stored and used for chain selection. The only implementation present in the codebase is the default instance for `StandardHash blk`:

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

The function ignores every field of `cert` — the round number, the boosted-block identity, the voter bitmap, and the aggregate BLS signature — and always returns `Right`. No quorum check, no signature verification, and no round-validity check is performed.

**Attacker-controlled entry path — object diffusion inbound handler**

Inbound Peras certificates arrive via the object-diffusion mini-protocol. The inbound handler `processCerts` calls the stub directly:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

Because `validatePerasCert mkPerasParams` always returns `Right`, every certificate in the batch is accepted, timestamped, and forwarded to `ChainDB.addPerasCertAsync`.

**How the accepted certificate affects chain selection**

Once a `ValidatedPerasCert` is stored in `PerasCertDB`, `implGetWeightSnapshot` builds a `PerasWeightSnapshot` from all stored certificates. This snapshot is consumed by `wsvTotalWeight` during chain selection:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [3](#0-2) 

The `wsvWeightBoost` is the sum of `weightBoostOfPoint` for every block on the candidate fragment that appears in the snapshot. A fake certificate for a block on an adversarial fork adds `perasWeight params` (default: 15) to that fork's total weight, making it preferred over the honest chain if the honest chain is not more than 15 blocks longer.

**`takeVolatileSuffix` is also affected**

The same snapshot is used by `takeVolatileSuffix` to determine which blocks are "immutable" (buried under weight ≥ k). A fake certificate can artificially inflate the weight of a block, causing the node to treat blocks that should still be volatile as immutable, preventing legitimate rollback. [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can send a single crafted `PerasCert` message (valid CBOR, any round number, any block hash) and cause the receiving node to:

1. **Prefer a non-canonical chain**: If the adversary's fork is within 15 blocks of the honest tip, the fake boost makes the adversarial chain's `wsvTotalWeight` exceed the honest chain's, triggering a chain switch.
2. **Prematurely finalize adversarial blocks**: The inflated weight can push adversarial blocks past the `k`-weight threshold in `takeVolatileSuffix`, making them appear immutable and preventing the node from ever rolling back to the honest chain.

This matches the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

- The attack requires only a single well-formed CBOR message over the existing object-diffusion mini-protocol; no stake, no keys, and no prior relationship with the target node are needed.
- The stub is in the production source tree and is wired into the live inbound handler with a `TODO` comment acknowledging the missing validation.
- The default `perasWeight` of 15 is large enough to overcome normal chain-density variance, making the attack reliably effective.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)` against the declared voter set.
2. Checks that the declared voters collectively hold stake above the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`) in the relevant epoch's stake distribution.
3. Verifies each voter's eligibility proof (VRF output for non-persistent committee members).
4. Rejects certificates whose `pcRoundNo` is outside the acceptable window relative to the current round.

Until the real implementation is in place, the inbound handler should refuse all peer-supplied certificates rather than silently accepting them.

---

### Proof of Concept

1. Connect to a target node running the Peras object-diffusion protocol.
2. Construct a `PerasCert` (CBOR list of 4 elements) with:
   - `pcRoundNo`: any `Word64`
   - `pcBoostedBlock`: the `(SlotNo, Hash)` of a block on an adversarial fork that is within 15 blocks of the honest tip
   - `pcVoters`: an empty or minimal voter structure (no real signatures needed)
   - `pcSignature`: a zeroed-out BLS aggregate signature
3. Send the certificate via the object-diffusion mini-protocol.
4. Observe that `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
5. The certificate is stored in `PerasCertDB`; the next chain-selection run reads the weight snapshot, finds the adversarial block boosted by `PerasWeight 15`, and switches to the adversarial fork. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L84-91)
```haskell
newtype PerasWeight
  = PerasWeight {unPerasWeight :: Word64}
  deriving Show via Quiet PerasWeight
  deriving stock Generic
  deriving newtype (Enum, Eq, Ord, NoThunks, Condense)

deriving via Sum Word64 instance Semigroup PerasWeight
deriving via Sum Word64 instance Monoid PerasWeight
```
