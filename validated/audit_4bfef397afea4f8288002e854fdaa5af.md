### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Fake Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` degenerate instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or committee-membership checks. Because the Peras cert diffusion mini-protocol is wired into the production node-to-node handler, any unprivileged peer can inject a crafted `PerasCert` targeting any block point. The fake certificate is stored in the `PerasCertDB`, its boost weight is applied to the `PerasWeightSnapshot`, and chain selection immediately re-evaluates candidates using the inflated weight — potentially causing an honest node to prefer a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

The sole `BlockSupportsPeras` instance (the degenerate catch-all for all block types) implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
```

No signature, no committee membership, no round-range, no boosted-block-existence check is performed. Every `PerasCert` value — regardless of content — is promoted to a `ValidatedPerasCert` carrying the full protocol boost weight. [1](#0-0) 

**Inbound path — cert diffusion mini-protocol calls `validatePerasCert` directly:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`. `processCerts` calls it on every new cert received from a peer; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`. [2](#0-1) [3](#0-2) 

**Production wiring — the handler is active for every peer connection:**

`hPerasCertDiffusionClient` in the production `Handlers` record calls `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB`, making the inbound cert path live for every node-to-node connection. [4](#0-3) 

**Chain selection consequence — fake boost alters `wsvTotalWeight`:**

`chainSelSync` stores the accepted cert in `PerasCertDB`, then calls `chainSelectionForBlock` for the boosted block. `preferAnchoredCandidate` switches from the normal (block-number-only) comparison to the weighted path as soon as `isEmptyPerasWeightSnapshot` is false. `wsvTotalWeight = blockNo + weightBoost`; a fake cert injects `PerasWeight 15` (the default `perasWeight` from `mkPerasParams`) onto any attacker-chosen block point. [5](#0-4) [6](#0-5) [7](#0-6) 

**Default boost magnitude:**

`mkPerasParams` sets `perasWeight = PerasWeight 15`. A single fake cert therefore makes a fork at block N appear heavier than the honest chain at block N+14. [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can inject one fake `PerasCert` per Peras round (one cert per round is stored; `perasRoundLength = 90` slots). Each fake cert boosts an attacker-chosen block by +15 weight units. By targeting blocks on a competing fork the attacker is also serving, the attacker can make that fork's `wsvTotalWeight` exceed the honest chain's, causing the victim node to switch to the attacker's fork. This is a **chain selection safety failure**: an honest node is made to prefer a non-canonical, potentially adversarially-controlled chain without any stake majority or cryptographic key compromise.

The impact matches: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

- **Preconditions:** A TCP connection to the target node. No keys, no stake, no privileged access required.
- **Trigger:** Send a `PerasCert` CBOR message over the Peras cert diffusion mini-protocol with `pcCertBoostedBlock` pointing to any block hash the attacker knows is in (or will enter) the victim's VolatileDB.
- **Constraint:** One cert per round is stored (deduplication by `PerasRoundNo`). With `perasRoundLength = 90` slots, an attacker accumulates +15 weight every ~90 seconds. A 15-block lead on the honest chain is overcome in ~22 minutes of sustained injection.
- **Peras enablement:** The cert diffusion handler is unconditionally wired up. Even if Peras is "disabled by default" at the era-params level, the inbound handler still accepts and stores certs, and `preferAnchoredCandidate` switches to weighted comparison the moment the weight snapshot is non-empty — which the attacker controls.

---

### Recommendation

1. **Enforce real validation before accepting any cert.** `validatePerasCert` must verify the aggregate committee signature, confirm the voter set meets quorum, and check that the boosted block's slot satisfies `perasBlockMinSlots`. Until the full committee-selection plumbing is in place, the function should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all).

2. **Gate the inbound handler on Peras being enabled.** If Peras is not active for the current era, `hPerasCertDiffusionClient` should be a no-op or should drop all inbound certs before they reach `processCerts`.

3. **Add a round-range check.** Even with full crypto, reject certs whose `pcCertRound` is outside the acceptable window (e.g., more than `perasCertMaxRounds` rounds old) before storing them.

---

### Proof of Concept

**Setup:** Two nodes A (honest) and B (attacker). A is at chain tip block N. B connects to A via the Peras cert diffusion mini-protocol.

**Step 1 — Attacker observes a block hash on a competing fork:**
B serves a fork to A via ChainSync. Let `h` be the hash of a block at height N−5 on B's fork that A has downloaded into its VolatileDB.

**Step 2 — Attacker sends a fake cert:**
B sends a CBOR-encoded `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint s h }` over the cert diffusion channel.

**Step 3 — Node A processes the cert:**
`processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`. The cert is forwarded to `ChainDB.addPerasCertAsync`.

**Step 4 — Chain selection re-runs:**
`chainSelSync` stores the cert, finds `h` in the VolatileDB, and calls `chainSelectionForBlock`. `preferAnchoredCandidate` now uses the weighted path. B's fork at height N−5 has `wsvTotalWeight = (N−5) + 15 = N+10`, which beats A's honest chain at height N (total weight N+0) if N < N+10 — i.e., always when the boost exceeds the honest chain's lead.

**Expected outcome:** Node A switches to B's fork, rolling back up to 5 blocks of honest chain. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
