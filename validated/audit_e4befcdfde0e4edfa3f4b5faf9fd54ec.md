### Title
Unconditional Certificate Acceptance in `validatePerasCert` Stub Enables Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every received `PerasCert`, skipping all cryptographic and semantic validation. Because Peras certificates directly drive chain selection weight boosts, an unprivileged peer can send a crafted certificate boosting any arbitrary block, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the required gate before a certificate is treated as a `ValidatedPerasCert` and used in chain selection. The production instance (the only instance, used for all block types via the `StandardHash blk` constraint) is:

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

This function accepts any `PerasCert` — regardless of whether it carries a valid aggregate signature, references a legitimately elected committee, or targets a real block — and wraps it in `ValidatedPerasCert` with the full `perasWeight` boost. No signature check, no committee membership check, no round-number check, and no boosted-block existence check is performed.

The analogous missing step to the ERC20 `approve()` call is the absent cryptographic verification of the certificate's aggregate vote signature and committee eligibility — the prerequisite that must succeed before the certificate is allowed to influence chain state.

---

### Impact Explanation

**Impact: High** — Chain selection manipulation by an unprivileged peer.

A `ValidatedPerasCert` is stored in the `PerasCertDB` and its `vpcCertBoost` is recorded in the `PerasWeightSnapshot`. Chain selection then uses `WeightedSelectView`, where `wsvTotalWeight` is the sum of block number and accumulated weight boost:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [2](#0-1) 

The `preferCandidate` function switches to a candidate chain whenever its `wsvTotalWeight` exceeds the current chain's:

```haskell
preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch ...
``` [3](#0-2) 

An attacker who sends a crafted certificate boosting a block on a shorter or non-canonical fork can make the node's `wsvTotalWeight` for that fork exceed the canonical chain's, triggering a chain switch to a non-canonical chain. This is a direct chain-selection safety failure driven by a network peer without any privileged access.

---

### Likelihood Explanation

**Likelihood: High**

- The Peras certificate diffusion mini-protocol (`ObjectDiffusion`) is a public network-facing interface; any connected peer can submit certificates.
- The stub is the **only** instance of `BlockSupportsPeras` (it is defined for all `StandardHash blk` via an overlapping instance), so there is no path through which real validation occurs.
- The TODO comment and linked issue (`https://github.com/tweag/cardano-peras/issues/120`) confirm this is a known placeholder, not a deliberate design choice.
- The `chainSelSync` path in `ChainSel.hs` directly processes received certificates and triggers chain selection:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

No validation gate stands between certificate receipt and chain selection execution.

---

### Recommendation

Implement the missing prerequisite validation steps inside `validatePerasCert` before constructing `ValidatedPerasCert`:

1. **Aggregate signature verification**: Verify the certificate's aggregate BLS/KES signature over the election ID and candidate block using the aggregated public keys of the claimed committee members.
2. **Committee membership check**: Confirm each claimed voter was a legitimate member of the Peras voting committee for the given round, using the stake distribution from the relevant epoch.
3. **Round and block validity**: Confirm the certificate's `pcCertRound` is within the valid range and that `pcCertBoostedBlock` refers to a known, non-genesis block.
4. **Quorum threshold**: Confirm the aggregate stake of the signers meets the `perasQuorumStakeThreshold`.

Only after all checks pass should `Right ValidatedPerasCert{...}` be returned. The `PerasValidationErr` type should be enriched with specific error variants (as noted in the existing TODO) to allow callers to distinguish and log failure reasons. [5](#0-4) 

---

### Proof of Concept

**Setup**: A private testnet with Peras enabled. Node A is on the canonical chain at block height 100. Node B (attacker) is on a fork at block height 95.

**Attack sequence**:

1. Attacker constructs a `PerasCert` with:
   - `pcCertRound` = any round number
   - `pcCertBoostedBlock` = the tip of the attacker's fork (block 95)
   - No valid aggregate signature (empty or random bytes)

2. Attacker sends this certificate to Node A via the Peras certificate diffusion mini-protocol.

3. Node A calls `validatePerasCert params cert`, which returns:
   ```haskell
   Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
   ```
   unconditionally. [6](#0-5) 

4. The certificate is stored in `PerasCertDB` and `chainSelectionForBlock` is triggered for the boosted block.

5. Node A's `WeightedSelectView` for the attacker's fork now has `wsvTotalWeight = 95 + perasWeight`, which may exceed the canonical chain's `wsvTotalWeight = 100 + 0` if `perasWeight` is large enough (e.g., `perasWeight > 5`).

6. Node A switches to the attacker's non-canonical fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-303)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```
