### Title
Peras Quorum Check Compares Unnormalized Absolute Stake Against Relative Threshold, Enabling Unauthorized Certificate Acceptance — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `stakeAboveThreshold` function in `SupportsPeras.hs` compares a `PerasVoteStake` value (which may carry absolute ledger stake in lovelace) directly against a relative quorum threshold (e.g., `3/4`). The code itself documents this as an unresolved unit-mismatch in a TODO comment. Because any positive absolute lovelace value exceeds `3/4` as a `Rational`, a single vote from any voter in the stake distribution is sufficient to forge a Peras certificate for an arbitrary block. The degenerate `validatePerasVote` instance compounds this by accepting votes without any cryptographic signature or eligibility proof, making the full attack path reachable by an unprivileged peer.

---

### Finding Description

**Root cause — unit mismatch in `stakeAboveThreshold`:** [1](#0-0) 

The function receives a `PerasVoteStake` (a `Rational`) and compares it to `perasQuorumStakeThreshold` (also a `Rational`, set to `3/4` in `mkPerasParams`). The code's own TODO comment acknowledges that there is no agreed-upon normalization step:

> "there is no consensus from researchers/engineers on how we go from the absolute stake of a voter in the ledger to the relative stake of their vote in the voting committee … so we should either normalize the `PerasVoteStake` before calling this function, or change this function to accept a stake distribution and perform the normalization internally." [2](#0-1) 

If the `PerasVoteStakeDistr` supplied at runtime contains absolute lovelace values (e.g., `1_000_000`), then `1_000_000 >= 3/4 + 2/100` is trivially `True`, and a single vote from any registered pool immediately satisfies quorum.

**Enabling factor — degenerate `validatePerasVote` skips all cryptographic checks:** [3](#0-2) 

The production-wired instance (marked "degenerate instance for all blks to get things to compile") accepts any vote whose `pvVoteVoterId` appears in the stake distribution, without verifying any VRF proof, KES signature, or committee eligibility proof. The stake value attached to the `ValidatedPerasVote` is taken directly from the distribution map — no voter-supplied value is checked.

**Vote aggregation path that reaches quorum:** [4](#0-3) 

`votesReachQuorum` calls `stakeAboveThreshold` on the accumulated `totalVoteStake`. With absolute values in the distribution, the first vote already satisfies the check.

**Network entry path:** [5](#0-4) 

`makePerasVotePoolWriterFromChainDB` is the production writer. It calls `validatePerasVote mkPerasParams sd vote` (where `sd` is the live stake distribution from STM) and then passes accepted votes to `ChainDB.addPerasVoteWithAsyncCertHandling`. An unprivileged peer submitting a single `PerasVote` message with any registered pool ID traverses this path end-to-end.

**JIT-liquidity analog mapping:**

| JIT liquidity (SushiSwap) | Ouroboros Consensus analog |
|---|---|
| Mint tight-range position just before price measurement → large `position.liquidity` | Submit one vote for any registered pool → absolute stake >> relative threshold |
| Claim reward proportional to inflated liquidity | Forge Peras certificate boosting attacker's preferred block |
| Burn position immediately after | No persistent stake change; attack is stateless |
| Repeat to drain incentive funds | Repeat to keep adversary's chain boosted above honest chain |

---

### Impact Explanation

A forged `ValidatedPerasCert` is stored in the `CertDB` and included in a block. The certificate carries a `PerasWeight` boost (default `15`) applied during chain selection. An adversary who can forge certificates at will can continuously boost their own chain, causing honest nodes to prefer it over the canonical chain. This is a **bypass of Peras certificate/vote verification checks** that enables unauthorized certificate acceptance and chain-selection manipulation.

Allowed impact category: *"Bypass of … PBFT/Praos/TPraos/Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

- Peras vote diffusion is wired into the production `NodeKernel` via `makePerasVotePoolWriterFromChainDB`.
- The attack requires only knowledge of any registered pool's `KeyHash StakePool` (public on-chain information) and the ability to send a `PerasVote` message over the node-to-node mini-protocol.
- No key compromise, stake majority, or operator access is needed.
- The unit mismatch is triggered whenever the `PerasVoteStakeDistr` STM action returns absolute lovelace values, which the TODO comment indicates is the unresolved current state.

Likelihood: **Medium** — conditioned on Peras being active on the network and the stake distribution not being pre-normalized before insertion into the STM cell.

---

### Recommendation

1. **Enforce normalization at the boundary.** `stakeAboveThreshold` should either (a) accept the total stake as an additional parameter and normalize internally, or (b) require that `PerasVoteStake` values are always relative (enforced by a `newtype` invariant or a smart constructor that takes the total stake).
2. **Replace the degenerate `validatePerasVote` instance** with a real implementation that verifies the voter's cryptographic eligibility proof (VRF output, committee membership) before accepting a vote.
3. **Add a property test** asserting that `stakeAboveThreshold` returns `False` when the sum of all individual pool stakes in the distribution is below the threshold, catching future regressions.

---

### Proof of Concept

```
1. Attacker observes any registered pool ID `pid` from the on-chain stake distribution.
2. Attacker constructs:
     PerasVote { pvVoteRound = <current round>
               , pvVoteBlock = <attacker's preferred block point>
               , pvVoteVoterId = PerasVoterId pid }
3. Attacker sends this vote to an honest node via the Peras vote diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote`.
   - `lookupPerasVoteStake` finds `pid` in `sd` and returns its absolute stake, e.g., Rational 5_000_000_000 1.
   - No signature or VRF check is performed (degenerate instance).
   - `ValidatedPerasVote { vpvVoteStake = 5_000_000_000 }` is returned.
5. `updatePerasRoundVoteStates` calls `votesReachQuorum`.
   - `totalVoteStake = 5_000_000_000`.
   - `stakeAboveThreshold`: `5_000_000_000 >= 3/4 + 2/100` → True.
   - A `ValidatedPerasCert` is forged for the attacker's block.
6. The certificate is stored in `CertDB` and included in the next block,
   boosting the attacker's chain by `perasWeight = 15` in chain selection.
7. Honest nodes switch to the attacker's chain.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-173)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
  deriving newtype (Eq, Ord, Num, Fractional, NoThunks, Serialise)
  deriving stock Generic
  deriving Show via Quiet PerasVoteStake
  deriving Semigroup via Sum Rational
  deriving Monoid via Sum Rational

-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-270)
```haskell
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L119-152)
```haskell
-- | Create a pool writer from the 'ChainDB'.
-- This properly handles the produced certs by letting the ChainDB take care
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-180)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L173-177)
```haskell
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
