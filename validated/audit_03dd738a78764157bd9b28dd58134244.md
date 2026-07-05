### Title
`validatePerasVote` Does Not Verify Voter Identity or Cryptographic Ownership, Allowing Any Peer to Forge Votes for Arbitrary Pool Operators — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation in the catch-all `BlockSupportsPeras` instance only checks that the claimed `pvVoteVoterId` exists in the stake distribution. It performs no cryptographic verification that the submitting peer actually controls the corresponding pool key. Because the `PerasVote blk` data type carries no signature field at all, any unprivileged peer can craft a vote claiming to be from any pool operator and have it accepted as valid by `processVotes`, the inbound vote handler that feeds the `PerasVoteDB` and triggers certificate generation.

---

### Finding Description

**Root cause — missing ownership validation in `validatePerasVote`:**

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase) defines `PerasVote blk` without a signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- claimed identity, no proof
  }
``` [1](#0-0) 

The corresponding `validatePerasVote` implementation only performs a stake-distribution lookup on the claimed voter ID:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

There is no signature field to verify, and no check that the sender is the legitimate owner of the claimed `PerasVoterId`. The TODO comment at line 350 explicitly acknowledges that actual validation is absent: [3](#0-2) 

**Attacker-controlled entry path — `processVotes`:**

Inbound votes from any peer are processed by `processVotes` in `PerasVote.hs`, which calls `validatePerasVote` on every new vote:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

This is wired into both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`, the production writers that feed the `PerasVoteDB` and `ChainDB` respectively: [5](#0-4) [6](#0-5) 

Once a vote passes `validatePerasVote`, it is stored as a `ValidatedPerasVote` and fed into `implAddVote`, which accumulates stake toward quorum and can trigger certificate generation: [7](#0-6) 

**Exploit flow:**

1. Attacker connects to a target node as an unprivileged peer.
2. Attacker enumerates pool IDs from the public stake distribution.
3. Attacker crafts `PerasVote` messages with `pvVoteVoterId` set to large-stake pool IDs and `pvVoteBlock` pointing to an attacker-chosen block.
4. `processVotes` calls `validatePerasVote`, which succeeds for every pool ID present in the stake distribution — no signature is checked.
5. Each forged vote is stored as `ValidatedPerasVote` with the legitimate pool's stake weight.
6. Once accumulated stake crosses the quorum threshold, `updatePerasRoundVoteStates` triggers `forgePerasCert`, producing a `ValidatedPerasCert` for the attacker-chosen block.
7. The certificate is inserted into the `ChainDB` via `addPerasCertAsync`, causing chain selection to apply a Peras weight boost to the attacker's chosen block. [8](#0-7) 

---

### Impact Explanation

**Critical.** This is a direct bypass of Peras vote authorization. An unprivileged peer with only network access can forge votes on behalf of any pool operator without possessing their keys. By accumulating enough forged stake weight, the attacker can cause a quorum certificate to be generated for an arbitrary block, forcing the victim node's chain selection to prefer that block via the Peras weight boost. This constitutes unauthorized certificate acceptance and a consensus safety failure — the node accepts a certificate that no legitimate committee member ever produced.

---

### Likelihood Explanation

**High.** The attack requires only:
- Network connectivity to a node running Peras vote diffusion.
- Knowledge of pool IDs in the stake distribution (publicly available on-chain).
- No cryptographic material, no stake, no special privileges.

The `processVotes` handler is directly reachable from the peer-facing object diffusion mini-protocol. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase and is unconditionally used for all block types.

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` (analogous to `VoteSignature crypto` used in the `WFALS`/`EveryoneVotes` committee implementations).
2. Implement `validatePerasVote` to verify that the signature in the vote was produced by the private key corresponding to the claimed `pvVoteVoterId`'s public key, as is done in `implVerifyVote` for the committee layer.
3. Until a proper signature scheme is in place, the degenerate instance must not be used in any production vote-diffusion code path.

---

### Proof of Concept

```
1. Node N is running Peras vote diffusion with stake distribution S.
2. Attacker A connects to N as a peer.
3. A observes that pool P has stake weight W > quorum_threshold.
4. A sends a single PerasVote { pvVoteRound = r, pvVoteBlock = B_attacker, pvVoteVoterId = P }.
5. processVotes calls validatePerasVote, which calls lookupPerasVoteStake.
   lookupPerasVoteStake finds P in S and returns W. Validation succeeds.
6. The vote is stored as ValidatedPerasVote with stake W.
7. updatePerasRoundVoteStates sees W >= quorum_threshold, calls forgePerasCert.
8. A ValidatedPerasCert for B_attacker is produced and inserted into ChainDB.
9. Chain selection applies Peras boost to B_attacker on node N.
``` [2](#0-1) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L241-270)
```haskell
-- It returns 'Nothing' if either of these conditions is not met.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-352)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```
