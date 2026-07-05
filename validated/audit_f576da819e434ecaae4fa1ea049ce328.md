### Title
`validatePerasCert` Unconditionally Accepts All Peer-Supplied Certificates, Enabling Unauthorized Chain-Selection Boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. This is the function called in the live production diffusion path when a peer sends a Peras certificate. Because no validation is performed, any unprivileged peer can send a crafted `PerasCert` boosting an arbitrary block, which is accepted, stored in the `PerasCertDB`, and used to inflate the weight of that block during chain selection — potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

`PerasParams` declares nine protocol parameters, including `perasBlockMinSlots` (minimum block age before it can be voted for), `perasCertMaxRounds` (maximum certificate age), `perasRoundLength`, and the quorum thresholds. These are all populated with concrete values in `mkPerasParams`. [1](#0-0) 

The `BlockSupportsPeras` class declares `validatePerasCert` as the mandatory gate that must accept or reject an inbound certificate before it enters the system: [2](#0-1) 

The universal instance — which covers all block types — implements this function as:

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
``` [3](#0-2) 

The `params` argument is received but none of its fields (`perasBlockMinSlots`, `perasCertMaxRounds`, `perasRoundLength`, quorum thresholds, etc.) are consulted. Every certificate, regardless of content, is wrapped in `Right` and returned as validated.

This stub is called directly in the **production** ObjectDiffusion pool writer for the ChainDB:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [4](#0-3) 

`processCerts` is designed to reject the entire batch if any certificate fails validation and disconnect the peer: [5](#0-4) 

Because `validatePerasCert` never returns `Left`, the rejection branch is unreachable. Every certificate from every peer passes.

Once accepted, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which triggers `chainSelSync`. That function looks up the boosted block in the VolatileDB and re-runs chain selection with the additional weight: [6](#0-5) 

Chain selection uses `WeightedSelectView`, where `wsvTotalWeight` is `BlockNo + weightBoost`. A crafted certificate with a large `vpcCertBoost` (derived from `perasWeight params`) can make a shorter, non-canonical chain appear heavier: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer connected via the ObjectDiffusion mini-protocol can send a `PerasCert` naming any block hash it knows (e.g., from a previously observed header). The certificate is accepted without any check on:
- Whether the round number is valid
- Whether the boosted block is old enough (`perasBlockMinSlots`)
- Whether the certificate is within its validity window (`perasCertMaxRounds`)
- Whether any quorum of votes actually backs it
- Any cryptographic signature or committee membership proof

The accepted certificate is stored and its boost is applied during chain selection. If the attacker targets a block on a fork, the node may switch to that fork, diverging from the canonical chain. This is a **High** impact: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The attack requires only that:
1. The node has Peras enabled via `rnFeatureFlags` (the intended deployment mode for Peras-enabled nodes).
2. The attacker is a connected peer (no keys, no stake, no special privileges required).
3. The attacker knows the hash of a block they wish to boost (trivially obtained from ChainSync headers).

No brute force, no key compromise, and no admin access is needed. The attacker simply constructs a `PerasCert` with the desired `pcCertRound` and `pcCertBoostedBlock` and sends it over the ObjectDiffusion protocol.

---

### Recommendation

The `validatePerasCert` implementation must be completed before Peras is enabled in any production deployment. At minimum, validation should enforce:

1. **Round validity**: the certificate's round number must correspond to a valid, past Peras round given the current slot and `perasRoundLength`.
2. **Block age**: the boosted block must be at least `perasBlockMinSlots` old.
3. **Certificate freshness**: the certificate's round must be within `perasCertMaxRounds` of the current round.
4. **Quorum proof**: the certificate must carry a verifiable proof that a quorum of stake (≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`) voted for the boosted block.
5. **Cryptographic integrity**: any BLS aggregate signature or committee selection proof must be verified.

Until these checks are implemented, the Peras feature flag must remain disabled in all production configurations.

---

### Proof of Concept

With Peras enabled, a peer executes the following logical steps:

1. Observe block hash `H` at slot `S` via ChainSync (no special access needed).
2. Construct `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint S H }` for any round `R`.
3. Send the certificate via the ObjectDiffusion mini-protocol.
4. On the receiving node, `processCerts` calls `validatePerasCert mkPerasParams cert`.
5. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }` unconditionally — no fields of `mkPerasParams` are checked.
6. The certificate is stored in `PerasCertDB` and `ChainDB.addPerasCertAsync` is called.
7. `chainSelSync` triggers chain selection for the boosted block; `weightBoostOfFragment` now adds `PerasWeight 15` to any chain containing block `H`.
8. If a fork containing `H` was previously lighter than the canonical chain, it may now be preferred, causing the node to roll back and switch chains.

The attacker can repeat this with multiple certificates targeting the same block to accumulate unbounded boost, since there is no per-round deduplication check in `validatePerasCert` and no limit on how many certificates can boost the same block. [3](#0-2) [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-131)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L100-105)
```haskell
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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
