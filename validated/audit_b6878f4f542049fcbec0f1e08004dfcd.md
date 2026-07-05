### Title
Stale `PerasCfg` Captured at DB Creation Causes Quorum Bypass After Peras Parameter Update - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs`)

---

### Summary

`createDB` captures the `PerasCfg blk` (which encodes the Peras quorum threshold) by value into the `addVote` closure at node startup. There is no mechanism to refresh this config when Peras protocol parameters change (e.g., at a hard-fork era transition). Accumulated vote state in `pvdsRoundVoteStates` was built against the old threshold; all subsequent votes are also evaluated against it. If the quorum threshold rises at a hard fork, an unprivileged peer can supply votes that satisfy the stale (lower) threshold, causing the local node to forge and accept a Peras certificate that does not meet the current protocol's quorum requirement, and to boost a chain that honest peers will not boost.

---

### Finding Description

In `createDB`, the `PerasCfg blk` value is extracted from `PerasVoteDbArgs` and immediately closed over in the `addVote` field of the returned `PerasVoteDB`:

```haskell
createDB args@PerasVoteDbArgs{pvdbaPerasCfg} = do
  ...
  pure PerasVoteDB
    { addVote = implAddVote pvdbaPerasCfg env   -- config frozen here
    , ...
    }
``` [1](#0-0) 

`implAddVote` receives this frozen `perasCfg` and passes it directly to `updatePerasRoundVoteStates`, which calls `updateCandidateVoteState`, which calls `votesReachQuorum cfg voteList` to decide whether to forge a certificate:

```haskell
updateCandidateVoteState cfg vote oldState =
  let newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
      voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
  in case votesReachQuorum cfg voteList of
       Just votesWithQuorum -> do
         cert <- forgePerasCert cfg votesWithQuorum
         ...
``` [2](#0-1) 

`votesReachQuorum` calls `stakeAboveThreshold cfg totalVoteStake`, so the quorum threshold is entirely determined by the frozen `PerasCfg`. [3](#0-2) 

The `PerasCfg` is part of the era-specific Peras parameters. The `EraParams` type already carries a `eraPerasRoundLength` field that is era-specific and can differ across hard-fork boundaries: [4](#0-3) 

When a hard-fork era transition occurs, the `PerasCfg` for the new era may carry a higher quorum threshold. Because `PerasVoteDB` was created with the old config and has no update path, every vote added after the transition is still evaluated against the pre-fork threshold. The `pvdsRoundVoteStates` map — which stores accumulated `PerasTargetVoteTally` and `PerasRoundVoteState` entries — was also built under the old threshold and is never re-evaluated. [5](#0-4) 

---

### Impact Explanation

If the quorum threshold rises at a hard fork, an adversary who can send Peras votes to the node (an unprivileged network peer, via the Peras vote mini-protocol) can supply exactly enough votes to satisfy the stale lower threshold. `implAddVote` will call `forgePerasCert` and store a `ValidatedPerasCert` in `pvdsRoundVoteStates`. This certificate is then propagated to chain selection via `addPerasVoteWithAsyncCertHandling`: [6](#0-5) 

The local node will use this under-quorum certificate to boost the targeted block's chain weight. Honest peers operating under the new (higher) threshold will not recognize this certificate as valid and will not boost the same block. The result is a chain-selection divergence: the compromised node prefers a chain that the rest of the honest network does not, weakening its security assumptions and potentially causing it to follow a non-canonical chain.

This maps to: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions**, and **Critical — bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance**.

---

### Likelihood Explanation

The attack requires a hard-fork era transition that raises the Peras quorum threshold, combined with a node that is not restarted across the transition (a restart would re-create the `PerasVoteDB` with the new config). Hard-fork transitions are a routine part of the Cardano lifecycle. An adversary who can send crafted votes (any network peer) and who knows the old threshold can trigger the condition deterministically. No key compromise or stake majority is required.

---

### Recommendation

Do not capture `PerasCfg` by value in the `addVote` closure. Instead, either:

1. **Pass `PerasCfg` as a call-time argument** to `addVote` (change the `PerasVoteDB` API so callers supply the current config on each call, analogous to how `keeperManagementFeeClaim` is called before updating fee params in the reference report).
2. **Flush and re-evaluate accumulated vote state** when the era transitions: before the new `PerasCfg` takes effect, drain `pvdsRoundVoteStates` by re-running `updatePerasRoundVoteStates` for all stored votes against the new config, or simply clear the DB (votes for rounds that have not yet reached quorum under the old threshold are unlikely to be valid under a stricter new threshold anyway).

The `PerasVoteDbArgs` type already has the right shape to accept a dynamic config source; the fix is to thread the current-era config through rather than freezing it at construction time. [7](#0-6) 

---

### Proof of Concept

1. Node starts in era N with Peras quorum threshold Q_old (e.g., 60 % of total stake).
2. A hard-fork transition to era N+1 raises the threshold to Q_new (e.g., 75 %).
3. The node does **not** restart; `PerasVoteDB` still holds `pvdbaPerasCfg` = config for era N.
4. An adversary sends votes for round R targeting block B, with combined stake S where Q_old ≤ S < Q_new.
5. `implAddVote` evaluates `votesReachQuorum cfg voteList` with the stale `cfg`; `stakeAboveThreshold cfg S` returns `True`.
6. `forgePerasCert cfg votesWithQuorum` is called; a `ValidatedPerasCert` is stored and forwarded to chain selection.
7. The local node boosts block B; honest peers (using Q_new) do not. The node diverges from the canonical chain. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L54-65)
```haskell
data PerasVoteDbState blk = PerasVoteDbState
  { pvdsVoteIds :: !(Set (PerasVoteId blk))
  , pvdsRoundVoteStates :: !(Map PerasRoundNo (PerasRoundVoteState blk))
  , pvdsVotesByTicket :: !(Map PerasVoteTicketNo (WithArrivalTime (ValidatedPerasVote blk)))
  -- ^ The votes by 'PerasVoteTicketNo'.
  --
  -- INVARIANT: In sync with 'pvsRoundVoteStates'.
  , pvdsLastTicketNo :: !PerasVoteTicketNo
  -- ^ The most recent 'PerasVoteTicketNo' (or 'zeroPerasVoteTicketNo' otherwise).
  }
  deriving stock (Show, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L124-135)
```haskell
type PerasVoteDbArgs :: (Type -> Type) -> (Type -> Type) -> Type -> Type
data PerasVoteDbArgs f m blk = PerasVoteDbArgs
  { pvdbaTracer :: Tracer m (TraceEvent blk)
  , pvdbaPerasCfg :: HKD f (PerasCfg blk)
  }

defaultArgs :: Applicative m => Incomplete PerasVoteDbArgs m blk
defaultArgs =
  PerasVoteDbArgs
    { pvdbaTracer = nullTracer
    , pvdbaPerasCfg = noDefault
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L145-162)
```haskell
createDB args@PerasVoteDbArgs{pvdbaPerasCfg} = do
  pvdeState <-
    newTVarWithInvariantIO
      (either Just (const Nothing) . invariantForPerasVoteDbState)
      initialPerasVoteDbState
  let env =
        PerasVoteDbEnv
          { pvdeTracer
          , pvdeState
          }
  pure
    PerasVoteDB
      { addVote = implAddVote pvdbaPerasCfg env
      , getVoteIds = implGetVoteIds env
      , getVotesAfter = implGetVotesAfter env
      , getForgedCertForRound = implGetForgedCertForRound env
      , garbageCollect = implGarbageCollect env
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L174-212)
```haskell
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-270)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EraParams.hs (L142-151)
```haskell
data EraParams = EraParams
  { eraEpochSize :: !EpochSize
  , eraSlotLength :: !SlotLength
  , eraSafeZone :: !SafeZone
  , eraGenesisWin :: !GenesisWindow
  , eraPerasRoundLength :: !(PerasEnabled PerasRoundLength)
  -- ^ Optional, as not every era will be Peras-enabled
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```
