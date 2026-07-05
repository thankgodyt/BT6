### Title
Stub `validatePerasCert` Unconditionally Accepts All Peer-Supplied Peras Certificates, Enabling Unauthorized Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural validation whatsoever. Because this stub is wired directly into the production Peras certificate diffusion inbound path (`processCerts` → `makePerasCertPoolWriterFromChainDB` → `addPerasCertAsync`), any unprivileged peer can inject a crafted `PerasCert` carrying an arbitrary `pcCertBoostedBlock` point, have it accepted as a `ValidatedPerasCert`, and cause the node to apply a weight boost to that block during chain selection. The companion `validatePerasVote` stub similarly omits all signature verification, allowing forged votes for any stakepool in the stake distribution to accumulate toward quorum and auto-generate a boosting certificate.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

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

Every `PerasCert blk` received from a peer is wrapped in `ValidatedPerasCert` and assigned the full `perasWeight params` boost without any check on the certificate's round number, boosted-block identity, quorum proof, or aggregate BLS signature.

**Root cause — `validatePerasVote` stub:** [2](#0-1) 

The vote type carries no signature field; `validatePerasVote` only checks that the `pvVoteVoterId` appears in the stake distribution. An attacker who knows any stakepool ID can forge votes for that pool for any `pvVoteBlock` without possessing the pool's private key.

**Production inbound path for certificates:** [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` is the production writer used by the Peras certificate diffusion mini-protocol. Its `opwAddObjects` field calls `processCerts … (validatePerasCert mkPerasParams)`, passing the stub directly. [4](#0-3) 

`processCerts` applies `validateCert` to every inbound certificate not already in the DB. Because the stub always returns `Right`, every certificate passes and is forwarded to `addCert` (or `ChainDB.addPerasCertAsync`).

**Chain-selection trigger:** [5](#0-4) 

`chainSelSync` processes the accepted certificate. After a slot-age check against the immutable tip, it adds the cert to `PerasCertDB`, then — if the boosted block is present in the `VolatileDB` — calls `chainSelectionForBlock` for that block. The `PerasWeightSnapshot` is updated with the full `perasWeight` boost, and `preferAnchoredCandidate` uses `wsvTotalWeight` (block-number + weight boost) to decide whether to switch forks. [6](#0-5) 

**End-to-end exploit flow:**

1. Attacker connects as an ordinary NTN peer.
2. Attacker sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = <fork tip> }` via the Peras certificate diffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
4. `addPerasCertAsync` enqueues the cert; `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for the fork tip.
5. The fork's `WeightedSelectView` now has `wsvTotalWeight = blockNo + 15`; if this exceeds the honest chain's total weight, the node switches to the attacker's fork.

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification enabling unauthorized chain-selection manipulation.**

An unprivileged peer can make an honest node permanently prefer a non-canonical fork by injecting a single crafted certificate. Because `perasWeight` is additive and certificates for the same round are deduplicated (one cert per round), the attacker can boost one block per Peras round. With `perasWeight = 15` and a round length of 90 slots, a sustained attacker can accumulate enough weight to keep a minority fork preferred over the honest chain, violating the chain-selection safety guarantee that Peras is designed to strengthen.

The companion vote-forgery path (no signature on `PerasVote`, `validatePerasVote` only checks stake-distribution membership) allows an attacker to forge votes for any known stakepool ID, accumulate quorum, and auto-generate a boosting certificate entirely within the node's own `PerasVoteDB`, without even needing to send a pre-formed certificate.

---

### Likelihood Explanation

**High.** The Peras certificate diffusion mini-protocol is active whenever Peras is enabled. The attacker requires only a standard NTN connection — no keys, no stake, no privileged access. The crafted certificate is a small CBOR-encoded struct (`pcCertRound :: PerasRoundNo`, `pcCertBoostedBlock :: Point blk`) that any peer can construct. The only existing guard is the slot-age check against the immutable tip, which is easily satisfied by targeting any recent block in the VolatileDB.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's aggregate BLS signature over `(electionId, candidate)` using the committee's aggregate verification key (as implemented in `implVerifyCert` in `WFALS.hs`).
- That `pcCertBoostedBlock` refers to a block that satisfies the `perasBlockMinSlots` age constraint.
- That `pcCertRound` is within the valid window (`perasCertMaxRounds`).

Similarly, add a signature field to `PerasVote blk` and implement signature verification in `validatePerasVote` before the stake-distribution lookup.

Until real validation is in place, gate the Peras certificate and vote diffusion paths behind a feature flag that is disabled by default in production builds, preventing untrusted peers from reaching the stub.

---

### Proof of Concept

```
-- Attacker constructs a minimal crafted certificate targeting a fork tip
-- known to be in the victim node's VolatileDB:
craftedCert :: PerasCert VictimBlock
craftedCert = PerasCert
  { pcCertRound      = PerasRoundNo currentRound
  , pcCertBoostedBlock = BlockPoint forkTipSlot forkTipHash
  }

-- Attacker sends craftedCert via the PerasCertDiffusion mini-protocol.
-- On the victim node:
--   processCerts ... (validatePerasCert mkPerasParams) ... [craftedCert]
--   => validatePerasCert mkPerasParams craftedCert
--   => Right (ValidatedPerasCert { vpcCert = craftedCert, vpcCertBoost = PerasWeight 15 })
--   => addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
--   => chainSelSync: PerasCertDB.addCert, then chainSelectionForBlock forkTipHdr
--   => forkTip.wsvTotalWeight = forkBlockNo + 15
--   => if forkBlockNo + 15 > honestTip.wsvTotalWeight: node switches to fork
``` [7](#0-6) [3](#0-2) [8](#0-7) [5](#0-4) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L319-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-87)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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
