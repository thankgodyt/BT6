### Title
Fraudulent Peras Certificate Accepted by Stub Validator Causes Chain Reorganization to Shorter Fork — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, `Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance unconditionally accepts every inbound `PerasCert` as valid. The production object-diffusion ingest path (`makePerasCertPoolWriterFromChainDB`) feeds this stub directly into `ChainDB.addPerasCertAsync`, which triggers `chainSelectionForBlock` with the fraudulent weight boost applied. Because `WeightedSelectView.preferCandidate` compares `blockNo + weightBoost`, a fork up to `perasWeight − 1 = 14` blocks shorter than the canonical chain will be preferred after a single injected certificate, causing the honest node to reorganize to the attacker-controlled fork.

---

### Finding Description

**Step 1 — Stub validator always returns `Right`** [1](#0-0) 

The degenerate instance (marked "TODO: degenerate instance for all blks to get things to compile", issue #73) implements `validatePerasCert` as:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No signature, quorum, committee membership, round validity, or boosted-block eligibility check is performed. Every structurally-decodable `PerasCert` is accepted and assigned the full `perasWeight = 15` boost. [2](#0-1) 

**Step 2 — Production ingest path uses the stub**

`makePerasCertPoolWriterFromChainDB` is the production writer used by the object-diffusion miniprotocol. It passes `validatePerasCert mkPerasParams` (the stub) to `processCerts`: [3](#0-2) 

`processCerts` calls `partitionEithers (validateCert <$> certsNotAlreadyInDb)`. Because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is forwarded to `ChainDB.addPerasCertAsync`. [4](#0-3) 

**Step 3 — `addPerasCertAsync` → `chainSelSync` → `chainSelectionForBlock`**

`addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message. `chainSelSync` processes it:

1. Checks the boosted block's slot is ≥ immutable tip slot (trivially satisfied for a recent fork block).
2. Adds the cert to `PerasCertDB` (no further validation).
3. Looks up the boosted block header in the VolatileDB.
4. If found, calls `chainSelectionForBlock` for that header. [5](#0-4) 

**Step 4 — Fraudulent weight boost enters `constructPreferableCandidates`**

`chainSelectionForBlock` reads the current `PerasWeightSnapshot` (which now includes the fraudulent cert's boost) and passes it to `constructPreferableCandidates` → `preferAnchoredCandidate`. [6](#0-5) 

**Step 5 — `WeightedSelectView.preferCandidate` switches to the shorter fork**

`wsvTotalWeight` is `PerasWeight(blockNo) + weightBoost`. With `perasWeight = 15`:

- Canonical chain tip at block N: `wsvTotalWeight = N + 0`
- Fork tip at block N−14 with fraudulent boost: `wsvTotalWeight = (N−14) + 15 = N+1`

`preferCandidate` returns `ShouldSwitch` because `N+1 > N`. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer that can send a single well-formed (but cryptographically fraudulent) `PerasCert` over the object-diffusion miniprotocol can cause an honest node to reorganize to a fork up to 14 blocks shorter than the canonical chain. This is a chain selection bypass: the node abandons a heavier honest chain in favour of a lighter attacker-controlled fork, violating the core Ouroboros security invariant that chain selection must only prefer a fork if it is genuinely heavier under honest protocol rules.

---

### Likelihood Explanation

The attack requires:
1. The attacker has already delivered the fork block (`B_fork`) to the victim's VolatileDB (via normal BlockFetch).
2. The attacker sends one `PerasCert` message pointing to `B_fork` via the object-diffusion miniprotocol.
3. The fork is between 1 and 14 blocks shorter than the canonical chain.

No stake, no keys, no admin access, and no brute force are required. The stub is in production source files and the object-diffusion path is fully wired. The only mitigating factor is that the Peras feature is not yet activated on mainnet Cardano; however, any testnet or development cluster running this code is immediately exploitable.

---

### Recommendation

1. **Remove or gate the degenerate instance**: The `validatePerasCert` stub must not be reachable from the production ingest path. Until real BLS aggregate-signature verification is implemented, the `makePerasCertPoolWriterFromChainDB` writer should refuse all inbound certs (return an error or no-op) rather than accept them unconditionally.
2. **Implement real `validatePerasCert`**: Verify the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)`, check committee membership and quorum, and validate round/slot eligibility before assigning any weight boost.
3. **Add a feature flag**: Gate the entire Peras cert ingest path behind an explicit protocol version or era check so that the stub cannot be reached on any network where real validation is not yet in place.

---

### Proof of Concept

Locally testable with `io-sim` or a two-node private testnet:

```
1. Start two nodes sharing a genesis. Let canonical chain reach block N.
2. Construct a fork of length N−14 (14 blocks shorter), deliver B_fork to node A via BlockFetch.
3. Craft PerasCert { pcCertRound = r, pcCertBoostedBlock = point(B_fork) }.
   (No valid BLS signature needed — the stub ignores it.)
4. Send the cert to node A via the object-diffusion miniprotocol.
5. Assert: node A's selected chain tip is now B_fork (14-block reorg).
6. Assert: with validatePerasCert replaced by a real verifier that rejects the cert,
   node A does NOT switch.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-634)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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
