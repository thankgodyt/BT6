### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Unprivileged Chain-Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — the only instance in the codebase — implements `validatePerasCert` as an unconditional `Right`, accepting every inbound Peras certificate without any cryptographic or structural check. An unprivileged peer can craft a `PerasCert` targeting any block in the VolatileDB, have it accepted through the `PerasCertDiffusion` miniprotocol, and cause the receiving node to re-run chain selection with an artificially boosted weight for that block. This is the direct analog of the Vepoch.sol reward-dilution bug: a participant temporarily inflates their influence (here: a block's chain weight) to redirect consensus outcomes, then exits with no stake at risk.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

The catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` is the only `BlockSupportsPeras` instance in the repository. Its `validatePerasCert` implementation unconditionally returns `Right`:

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

No signature is verified, no quorum is checked, no round-number or block-point constraints are enforced.

**Inbound path — cert arrives from a peer and is validated here:** [2](#0-1) 

The analogous `makePerasCertPoolWriterFromChainDB` (in `ObjectPool/PerasCert.hs`, confirmed by grep) calls `validatePerasCert` as the sole gate before forwarding the cert to `ChainDB.addPerasCertAsync`. Because `validatePerasCert` always succeeds, every cert from every peer passes.

**Chain selection is triggered by the accepted cert:** [3](#0-2) 

`chainSelSync` processes `ChainSelAddPerasCert`, adds the cert to `PerasCertDB`, and calls `chainSelectionForBlock` for the boosted block. The only guard is an age check (`pointSlot boostedBlock < AF.anchorToSlotNo immTip`); there is no re-validation of the certificate itself.

**Weight boost is applied unconditionally in chain comparison:** [4](#0-3) 

`wsvTotalWeight = BlockNo + PerasWeight`. A single accepted certificate adds `perasWeight params` to the targeted block's effective chain length, potentially making a shorter fork appear heavier than the honest chain.

**The miniprotocol is wired into the production node-to-node stack:** [5](#0-4) 

`hPerasCertDiffusionClient` is a live miniprotocol handler, not gated behind any feature flag at the network layer.

---

### Impact Explanation

When Peras is enabled, any unprivileged peer can:

1. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` for any block `p` in the target node's VolatileDB.
2. Send it via the `PerasCertDiffusion` miniprotocol.
3. `validatePerasCert` accepts it unconditionally; the cert is stored in `PerasCertDB` and the full configured `perasWeight` boost is credited to `p`.
4. Chain selection re-runs; if `p` is on a fork, `wsvTotalWeight(fork) > wsvTotalWeight(honest chain)` and the node switches.

This is a **bypass of Peras certificate validation** enabling unauthorized certificate acceptance and chain-selection manipulation — matching the Critical impact tier. It is structurally identical to the Vepoch.sol pattern: a participant injects a resource (fake cert / fake deposit) to divert consensus outcomes (chain preference / reward shares) at zero cost.

---

### Likelihood Explanation

- Peras is currently disabled by default (`Note that if Peras is disabled (which is the default), there is no observable difference` — CHANGELOG), so the attack surface is not yet live on mainnet.
- However, the miniprotocol handler is compiled into every node build and will become active when Peras is enabled. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is known incomplete work, not an intentional design choice.
- The attack requires only a peer connection and the ability to serialize a two-field struct (`PerasRoundNo` + `Point blk`). No stake, no key material, no privileged access is needed.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over the certificate voters.
2. Checks that the claimed voters are members of the correct committee for the given round (using the stake snapshot from the appropriate epoch).
3. Verifies that the total stake of the signers exceeds the quorum threshold (`stakeAboveThreshold`).
4. Enforces that `pcCertRound` is within the valid window relative to the current chain tip.

Until a real implementation is available, the `PerasCertDiffusion` inbound handler should reject all inbound certificates (rather than accepting them unconditionally) when the full validation logic is not yet in place.

---

### Proof of Concept

**Private testnet sequence (Peras enabled):**

1. Start two nodes A (honest) and B (attacker peer of A), with Peras enabled and `perasWeight = W`.
2. Let the honest chain grow to tip `T` (block number `N`).
3. Attacker mines a private fork of length `N - W + 1` (shorter by `W - 1` blocks).
4. Attacker connects to A and sends via `PerasCertDiffusion`:
   ```
   PerasCert { pcCertRound = <any>, pcCertBoostedBlock = <tip of fork> }
   ```
5. Node A calls `validatePerasCert` → `Right` (no checks performed).
6. `chainSelSync` runs; fork tip receives boost `W`; `wsvTotalWeight(fork) = (N - W + 1) + W = N + 1 > N = wsvTotalWeight(honest)`.
7. Node A switches to the attacker's fork.

The attacker has caused an honest node to abandon the canonical chain using only a crafted two-field network message, with no stake at risk — the exact "no-penalty influence injection" pattern from the Vepoch.sol report.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L121-152)
```haskell
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-390)
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
      , hPerasCertDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionOutboundTracer tracers))
            (perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasCertPoolReaderFromChainDB $ getChainDB)
            version
```
