### Title
`validatePerasVote` Accepts Peer-Supplied `pvVoteVoterId` Without Signature Verification, Enabling Vote Forgery for Any Registered Pool - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasVote` function accepts inbound `PerasVote` messages from peers and validates them solely by checking whether the attacker-controlled `pvVoteVoterId` field is present in the stake distribution. The `PerasVote blk` wire type carries no cryptographic signature field, and no ownership proof is verified. Any unprivileged peer can craft a `PerasVote` claiming to be from any registered pool and have it accepted as a valid, stake-weighted vote, enabling quorum forgery for an arbitrary block.

---

### Finding Description

**Root cause — no signature field and no ownership check in `validatePerasVote`.**

The `PerasVote blk` data type defined in the `BlockSupportsPeras` instance contains only three fields:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- fully attacker-controlled
  }
```

There is no signature field. [1](#0-0) 

The `validatePerasVote` implementation (the only validation gate before a vote is admitted to the pool) performs a single stake-distribution lookup keyed on the attacker-supplied `pvVoteVoterId`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` simply does `Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)` — it never touches a cryptographic key. [3](#0-2) 

This is the exact structural analog of the external report: just as `rebalance` accepted a caller-supplied `account` and used it as the authoritative payer without proving the caller controlled that account, `validatePerasVote` accepts a peer-supplied `pvVoteVoterId` and uses it as the authoritative voter identity without proving the peer controls the corresponding key.

**Reachable entry path.**

`validatePerasVote` is wired directly into the Peras vote diffusion inbound handler via `makePerasVotePoolWriterFromChainDB`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

`processVotes` is the inbound batch handler called for every batch of votes received from a peer. [5](#0-4) 

**Exploit flow.**

1. Attacker connects to a node as a peer via the Peras vote object-diffusion miniprotocol.
2. Attacker crafts `PerasVote` messages setting `pvVoteVoterId` to the `KeyHash StakePool` of any registered pool (public on-chain information).
3. `processVotes` calls `validatePerasVote`; the only check is `Map.lookup voterId stakeDistr` — it succeeds for any registered pool.
4. Each fake vote is admitted as a `ValidatedPerasVote` carrying the impersonated pool's full `PerasVoteStake`.
5. Once `votesReachQuorum` returns `Just`, `forgePerasCert` is called and a certificate is produced for the attacker's chosen block. [6](#0-5) 
6. The forged certificate is inserted into the `ChainDB` and influences chain selection.

A concrete instance: the `PerasVoteId` is `(pvVoteRound, pvVoteVoterId)`. Because there is no signature, the attacker can submit one fake vote per registered pool per round, accumulating the full stake of the entire active pool set and trivially exceeding any quorum threshold.

---

### Impact Explanation

**Critical — bypass of Peras vote/certificate authorization enabling unauthorized certificate acceptance.**

An unprivileged peer can:
- Forge valid-looking votes attributed to any registered pool without possessing their BLS keys.
- Accumulate stake-weighted votes exceeding the quorum threshold in a single round.
- Cause the node to forge and accept a `PerasCert` for an arbitrary block of the attacker's choice.
- Drive chain selection toward a non-canonical or adversarially chosen chain, constituting a consensus safety failure.

This matches the allowed impact scope: *"Bypass of … certificate/vote verification bypass … that enables unauthorized … vote, or certificate acceptance."*

---

### Likelihood Explanation

- **No privileged access required**: any peer reachable via the Peras vote diffusion miniprotocol can execute this.
- **No cryptographic material required**: pool key hashes (`KeyHash StakePool`) are public on-chain data.
- **Trivially automatable**: a single connection and a loop over the stake distribution suffices.
- The code is in the production codebase and is the active instance used for all block types (`instance StandardHash blk => BlockSupportsPeras blk`). [7](#0-6) 

---

### Recommendation

1. **Add a mandatory signature field** to `PerasVote blk` (analogous to `pvSignature` in `Ouroboros.Consensus.Peras.Vote.V1.PerasVote`). [8](#0-7) 
2. **Verify the signature in `validatePerasVote`** against the public key retrieved from the stake distribution for the claimed `pvVoteVoterId`, before admitting the vote.
3. **Use `msg.sender`-equivalent logic**: derive the voter identity from the verified signature rather than accepting it as a self-reported field in the message — exactly the fix recommended in the external report.
4. The `WFALS.implVerifyVote` and `EveryoneVotes.implVerifyVote` implementations already demonstrate the correct pattern: look up the public key from trusted committee state, then call `verifyVoteSignature`. [9](#0-8)  The `BlockSupportsPeras` instance must apply the same pattern.

---

### Proof of Concept

```
Precondition: attacker has a TCP connection to a node running the Peras
vote diffusion miniprotocol.

1. Query the on-chain stake distribution to obtain all PerasVoterId values
   (KeyHash StakePool) with positive stake.

2. For target round R and target block B, construct for each pool P_i:
     PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = P_i }
   No signing key is needed; the struct has no signature field.

3. Send the batch to the node via the object-diffusion inbound handler.

4. processVotes calls validatePerasVote for each vote.
   validatePerasVote succeeds for every P_i present in the stake distribution
   (the only check is Map.lookup pvVoteVoterId stakeDistr).

5. Each vote is stored as a ValidatedPerasVote with the full stake of P_i.

6. votesReachQuorum detects that total stake > quorum threshold.

7. forgePerasCert produces a PerasCert for block B at round R.

8. The certificate is inserted into ChainDB; chain selection is influenced
   toward B regardless of whether B is the honest canonical tip.

Expected outcome: node accepts a Peras certificate for an attacker-chosen
block without any legitimate pool having cast a vote.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-265)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-321)
```haskell
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-350)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
```
