### Title
Peras Vote Validation Accepts Votes Without Verifying Voter Identity — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function checks that the claimed `pvVoteVoterId` exists in the stake distribution, but the `PerasVote` data type carries no cryptographic signature and no proof of voter identity. Any unprivileged peer can craft a `PerasVote` message claiming to be any registered stake pool, pass validation, and have that vote counted toward quorum — without ever controlling the claimed pool's keys. This is the direct analog of the external report: the system validates entity A (the claimed voter ID is registered) but applies the effect (vote acceptance and stake credit) without verifying that the sender is actually entity A.

---

### Finding Description

`validatePerasVote` in `SupportsPeras.hs` (lines 360–371):

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

The `PerasVote` data type (lines 330–336) has no signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound :: PerasRoundNo
  , pvVoteBlock :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- claimed identity, never proven
  }
```

`lookupPerasVoteStake` (lines 196–203) simply does a `Map.lookup` on `pvVoteVoterId` in the stake distribution — it performs no cryptographic check whatsoever. The function ignores `_params` entirely and never touches any signing key or proof.

The production entry path is `processVotes` in `PerasVote.hs` (lines 170–180), called from both `makePerasVotePoolWriterFromVoteDB` (line 111) and `makePerasVotePoolWriterFromChainDB` (line 141), which wire in `validatePerasVote mkPerasParams sd vote` as the validator for every inbound vote received over the network.

The external-report analog is exact:
- **External report**: `receiver` is checked for whitelist membership, but tokens flow to `msg.sender` — a different party.
- **Here**: `pvVoteVoterId` is checked for stake-distribution membership (entity A), but the vote is accepted and credited without verifying that the network sender (entity B) controls entity A's keys.

---

### Impact Explanation

An unprivileged peer can send `PerasVote` messages claiming to be any registered stake pool. Each such forged vote passes `validatePerasVote` and is stored as a `ValidatedPerasVote` with the real pool's `PerasVoteStake`. Once enough forged votes accumulate, `votesReachQuorum` (lines 247–265) returns a `ValidatedPerasVotesWithQuorum`, `forgePerasCert` produces a `ValidatedPerasCert`, and the ChainDB applies the Peras boost (`vpcCertBoost = perasWeight params`) to the attacker-chosen block. Honest nodes then prefer that boosted chain over the canonical chain, constituting a chain-selection safety failure driven entirely by a single unprivileged peer.

**Impact class**: High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

The vulnerable code path is compiled into the production binary and wired into the live diffusion layer via `makePerasVotePoolWriterFromChainDB`. The `PerasVote` wire format is already serialised/deserialised (lines 411–424 of `SupportsPeras.hs`), meaning the network-facing surface is active. Peras vote diffusion is gated only by whether the node operator enables the Peras mini-protocol; once that flag is set, any peer on the network can exploit this with a single crafted message. No stake, no keys, and no prior relationship with the target node are required.

---

### Recommendation

1. Add a `pvVoteSignature` field (or equivalent cryptographic proof) to `PerasVote`.
2. In `validatePerasVote`, after confirming the voter ID is in the stake distribution, retrieve the voter's public key and verify the signature over `(pvVoteRound, pvVoteBlock, pvVoteVoterId)`.
3. Until the full committee-selection context is available (as noted in the TODO), at minimum reject any vote whose voter ID cannot be bound to a verifiable signature — do not return `Right` for structurally unsigned votes.
4. Mirror the pattern already used in `implVerifyVote` for `EveryoneVotes` (lines 211–232 of `EveryoneVotes.hs`), which correctly calls `verifyVoteSignature` against the voter's public key before returning an eligibility witness.

---

### Proof of Concept

1. Attacker connects to an honest node with Peras vote diffusion enabled.
2. Attacker reads the current `PerasVoteStakeDistr` (publicly available via the ledger state query mini-protocol) and identifies a high-stake pool `V` with `PerasVoterId` = `vid`.
3. Attacker crafts `PerasVote { pvVoteRound = r, pvVoteBlock = attacker_block, pvVoteVoterId = vid }` — no signing key for `V` is needed.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; `lookupPerasVoteStake` finds `vid` in `sd` and returns `Just stake`; `validatePerasVote` returns `Right (ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake })`.
5. Attacker repeats step 3–4 for enough distinct pool IDs to satisfy `stakeAboveThreshold`.
6. `votesReachQuorum` returns `Just ValidatedPerasVotesWithQuorum`; `forgePerasCert` produces a cert boosting `attacker_block`.
7. The honest node's chain selection now weights `attacker_block` above the canonical tip, causing a divergence from the honest chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L247-265)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L211-232)
```haskell
implVerifyVote committee = \case
  EveryoneVotesVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVerificationKey
            electionId
            candidate
            sig
        case nonZero voterStake of
          Nothing ->
            Left (PoolHasNoStake seatIndex)
          Just nonZeroVoterStake ->
            pure $
              EveryoneVotesMember
                seatIndex
                nonZeroVoterStake
    | otherwise ->
        Left (MissingSeatIndex seatIndex)
```
