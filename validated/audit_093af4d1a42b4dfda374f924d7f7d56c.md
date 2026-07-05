### Title
Missing Cryptographic Signature Validation in Peras Vote Processing Allows Vote Forgery by Any Peer - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` function performs no cryptographic signature verification on inbound Peras votes. The `PerasVote` data type carries no signature field, and the validation function only checks stake-distribution membership. Any unprivileged peer can forge votes attributed to any registered stake pool and inject them into the live vote-diffusion pipeline, potentially manufacturing a quorum for an arbitrary block and corrupting Peras-driven chain selection.

---

### Finding Description

**Root cause — missing signature field and missing signature check**

The universal `BlockSupportsPeras` instance defines the `PerasVote` associated data type without any cryptographic proof of authenticity:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound :: PerasRoundNo
  , pvVoteBlock :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- only a pool key-hash; no signature
  }
``` [1](#0-0) 

The corresponding `validatePerasVote` implementation accepts any vote whose `pvVoteVoterId` appears in the stake distribution, with no further checks:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

This is the **only** `BlockSupportsPeras` instance in the codebase — it is the catch-all `instance StandardHash blk => BlockSupportsPeras blk`. [3](#0-2) 

**Attacker-controlled entry path**

Inbound votes from peers flow through `processVotes` in the object-diffusion layer, which calls `validatePerasVote` directly:

```haskell
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

`processVotes` is the live inbound handler for peer-submitted votes; it throws a `PerasVoteInboundException` only when `validatePerasVote` returns `Left`, which never happens for any `pvVoteVoterId` present in the public stake distribution. [5](#0-4) 

Accepted votes are stored in `PerasVoteDB` via `implAddVote`, which aggregates them toward quorum: [6](#0-5) 

Once quorum is reached, a `ValidatedPerasCert` is forged and stored, boosting the attacker-chosen block in chain selection.

**Analog to the external report**

The external report identifies that `Amp.authorizeOperatorByPartition` lacks `require(_operator != msg.sender)`, allowing self-authorization without proper validation. The analog here is that `validatePerasVote` lacks `verifyVoteSignature`, allowing vote attribution to any pool without proper validation. Both are cases of **missing input validation** that permit unauthorized state changes through a publicly reachable entry point.

---

### Impact Explanation

**High — Chain selection / Peras boosting corruption.**

An unprivileged peer can:
1. Enumerate the public stake distribution (it is public ledger state).
2. Craft `PerasVote` messages claiming to be from high-stake pools, targeting any block point.
3. Submit enough forged votes to exceed the quorum threshold (`stakeAboveThreshold`).
4. Cause the node to forge a `ValidatedPerasCert` boosting the attacker-chosen block.
5. Peras boosting directly influences chain selection weight, potentially causing an honest node to prefer a non-canonical or adversarially chosen chain.

This satisfies the **High** impact criterion: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

**High.** The stake distribution is public. The `PerasVote` wire format is serializable and trivially constructable. The object-diffusion protocol is active and accepts batches of votes from any connected peer. No key material, stake, or privileged access is required — only knowledge of pool key-hashes present in the current stake distribution, which are observable on-chain.

---

### Recommendation

1. **Add a signature field** to the `PerasVote` associated data type (or require it via the `BlockSupportsPeras` class contract), so that each vote carries a cryptographic proof that the claimed `pvVoteVoterId` actually signed the `(pvVoteRound, pvVoteBlock)` tuple.
2. **Implement signature verification** in `validatePerasVote` before accepting a vote as `ValidatedPerasVote`. The `CryptoSupportsVoteSigning` / `verifyVoteSignature` infrastructure already exists in `Ouroboros.Consensus.Committee.Crypto` and should be wired in here.
3. **Remove or gate** the degenerate catch-all `instance StandardHash blk => BlockSupportsPeras blk` so that blocks without a real Peras implementation cannot accidentally use the no-op validator in a live network context. [7](#0-6) 

---

### Proof of Concept

**Setup:** A node running with the default `BlockSupportsPeras` instance connected to the Peras vote-diffusion network.

**Steps:**

1. Observe the current `PerasVoteStakeDistr` (public ledger state); collect pool key-hashes `[v₁, v₂, …, vₙ]` with their associated stakes.
2. Determine the current Peras round `r` and a target block point `B` (e.g., a block on a minority fork).
3. For each `vᵢ` whose stake contributes toward quorum, construct:
   ```
   PerasVote { pvVoteRound = r, pvVoteBlock = B, pvVoteVoterId = vᵢ }
   ```
   No signing key is needed; the struct has no signature field.
4. Send the batch to the victim node via the object-diffusion mini-protocol.
5. `processVotes` calls `validatePerasVote` for each vote; each passes because `lookupPerasVoteStake` finds `vᵢ` in the distribution.
6. `implAddVote` / `updatePerasRoundVoteStates` accumulates stake; once `stakeAboveThreshold` is satisfied, a `ValidatedPerasCert` boosting `B` is forged and stored.
7. The Peras boost for `B` influences chain selection, causing the node to prefer the attacker-chosen block.

**Expected outcome:** The victim node boosts and potentially selects block `B` without any legitimate committee member having actually voted for it.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-217)
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
        -- Added vote but did not generate a new certificate, either
        -- because quorum was not reached yet, or because this vote was
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs (L151-190)
```haskell
-- * Aggregate verification interface

--
-- NOTE: vote signatures and VRF outputs are treated asymmetrically here.
--
-- On one hand, individual vote signatures are used to prove the identity of
-- of their issuers for a given election and candidate being voted for. When
-- forging a certificate, we might want to aggregate the signatures of multiple
-- voters that participated in the same election and voted for the same
-- candidate into a single aggregate signature that attests the participation of
-- the entire group of voters. Such a signature is much smaller than the sum of
-- the individual signatures of each voter, and can be verified more efficiently
-- than verifying each individual signature separately. To do so, verifiers will
-- first need to create an aggregate verification key by combining the
-- verification key of each voter in the group (whose identity will likely have
-- to be declared in the corresponding certificate), and then verify the
-- aggregate signature using the aggregate verification key in a single step.
-- Note that since all voters sign the same thing (election ID and candidate),
-- swapping the signatures of two voters in the group would not have any effect
-- on the aggregate signature.
--
-- On the other hand, VRF outputs attest both the eligibility of a single voter
-- to participate in a given election /and/ the number of seats they are
-- entitled to in such election (which can directly affect their voting power).
-- Because of this, their VRF outputs cannot be aggregated into a single one
-- when forging a certificate, and must instead be included individually. When
-- verifying a certificate, however, we can still take advantage of aggregation
-- to verify the VRF outputs of all voters in a single step, but since each VRF
-- output might grant each voter a different number of seats, we need to be
-- careful about swap-attacks. This is where an adversary could swap their VRF
-- output with someone else's before forging a certificate, stealing their
-- (more favorable) eligibility proof. To avoid this, the interface for batch
-- VRF verification explicitly expects unaggregated VRF verification keys and
-- VRF outputs, so that the implementation should be able to first bind each
-- VRF output to the corresponding voter's verification key via linearization.
-- In layman terms, this means multiplying each VRF output by a unique scalar
-- before aggregating them. This enforces that, during verification, the order
-- of the VRF outputs must match the order of the verification keys verification
-- keys, thus avoiding any attempt of swapping VRF outputs between voters.

```
