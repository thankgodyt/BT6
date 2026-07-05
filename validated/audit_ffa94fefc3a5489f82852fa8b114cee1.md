### Title
Stub Peras Certificate Validation Allows Unprivileged Peer to Manipulate Chain Selection via Arbitrary Weight Boosts — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The Peras certificate validation function (`validatePerasCert`) is an unimplemented stub that unconditionally accepts every certificate. Any unprivileged peer connected via the object-diffusion mini-protocol can submit a crafted `PerasCert` for any block in the volatile window. Because the certificate is accepted without cryptographic or committee verification, it is stored in `PerasCertDB` and its weight boost is immediately incorporated into `WeightedSelectView`-based chain selection. A sufficiently large boost can make an adversarial fork appear heavier than the honest chain, causing the node to switch to it.

This is the consensus analog of the `matchOrders()` front-running report: just as any caller could exploit the open ordering function to profit from price differences, any peer can exploit the open certificate-submission path to shift chain selection in their favour.

---

### Finding Description

**1. Stub validation always returns `Right`**

The default implementation of `validatePerasCert` in the `BlockSupportsPeras` typeclass carries an explicit TODO and returns `Right` for every input:

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

**2. Object-diffusion inbound path uses the stub**

`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` both call `processCerts` with `validatePerasCert mkPerasParams` — the same stub — and a second TODO acknowledges the placeholder:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` accepts the entire batch if all certificates pass `validateCert`; since the stub never fails, every peer-supplied certificate is timestamped and forwarded to `addCert`: [3](#0-2) 

**3. Accepted certificate is stored and triggers chain selection**

`chainSelSync` for `ChainSelAddPerasCert` adds the certificate to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

**4. Chain selection compares total weight including the boost**

`WeightedSelectView.preferCandidate` compares `wsvTotalWeight`, which is `blockNo + weightBoost`. A fork whose boosted block receives a large `PerasWeight` can exceed the total weight of the current (longer) honest chain:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch ...
``` [5](#0-4) 

`wsvTotalWeight` is defined as:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [6](#0-5) 

**5. The weight snapshot used during chain selection is read at the start of `chainSelectionForBlock`**

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [7](#0-6) 

Because the certificate was already committed to `PerasCertDB` before this read, the adversarial boost is visible to the snapshot and is used to rank candidates.

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Identify a block on a minority fork within the volatile window (up to `k` weight from the immutable tip).
2. Craft a `PerasCert` claiming that block is boosted by an arbitrarily large `PerasWeight`.
3. Submit it via the object-diffusion protocol; `processCerts` accepts it unconditionally.
4. The certificate is stored; `chainSelectionForBlock` is triggered for the boosted block.
5. `preferCandidate` computes `wsvTotalWeight` for the fork as `blockNo + adversarialBoost`, which can exceed the honest chain's total weight.
6. The node rolls back to the fork, adopting an adversarial or non-canonical chain.

This is a **chain selection error** that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions (High impact per scope).

---

### Likelihood Explanation

- Peras is disabled by default but is a first-class, production-targeted feature with full ChainDB integration already merged.
- The attack path (connect as a peer → send a `PerasCert` object → trigger chain selection) requires no special privileges, no stake, and no cryptographic material.
- The stub is explicitly marked TODO with a linked issue, confirming it is known-incomplete production code, not a test helper.
- Any node operator who enables Peras (or any future deployment where Peras is on by default) is immediately exposed.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the BLS aggregate signature over the committee's public keys, check that the signing committee was legitimately elected for the claimed round, and confirm the boosted block hash matches the certificate's claimed target.
2. Until real validation is in place, **gate the object-diffusion inbound path** so that `processCerts` rejects all certificates when Peras validation is not yet implemented, rather than silently accepting them.
3. Add a property-based test that submits a certificate with an arbitrary boost for a minority-fork block and asserts the node does not switch away from the honest chain.

---

### Proof of Concept

**Setup (private testnet with Peras enabled):**

1. Run two nodes, A (honest) and B (adversary). Both are on the same chain at block height H.
2. Adversary B withholds one block, creating a 1-block fork at height H+1 (fork block `F`).
3. Honest node A extends to H+2 on the main chain (total weight = H+2).

**Attack:**

4. B constructs a `PerasCert { pcCertRound = R, pcCertBoostedBlock = blockPoint F }` with `vpcCertBoost = PerasWeight (H + 10)` (any value exceeding A's current total weight).
5. B sends this certificate to A via the Peras object-diffusion protocol.
6. A's `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
7. A stores the certificate; `chainSelSync (ChainSelAddPerasCert ...)` fires.
8. `chainSelectionForBlock` reads the weight snapshot: fork block `F` now has total weight `1 + (H+10) = H+11 > H+2`.
9. `preferCandidate` returns `ShouldSwitch`; A rolls back to `F` and adopts B's fork.

**Relevant code path:**
- Entry: [8](#0-7) 
- Stub acceptance: [1](#0-0) 
- Chain selection trigger: [9](#0-8) 
- Weight comparison: [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L494-531)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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
