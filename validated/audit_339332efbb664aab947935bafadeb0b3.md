### Title
Missing Cryptographic Signature Verification in `validatePerasVote` Allows Unprivileged Peer to Forge Votes on Behalf of Any Registered Pool - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function in the `BlockSupportsPeras` type-class default implementation only checks whether the claimed voter ID exists in the stake distribution. It performs **no cryptographic signature verification** on the vote body. An unprivileged peer connected via the ObjectDiffusion mini-protocol can craft `PerasVote` messages claiming to be from any registered stake pool, have them accepted as `ValidatedPerasVote`, stored in the `PerasVoteDB`, and—once enough forged votes accumulate—trigger false quorum and the forging of a fraudulent Peras certificate that manipulates chain selection.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasVote` with a default implementation: [1](#0-0) 

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

The only check performed is `lookupPerasVoteStake`, which looks up the vote's `pvVoteVoterId` (a pool key hash) in the stake distribution map: [2](#0-1) 

No cryptographic signature on the vote body is verified. The TODO comment in the same file explicitly acknowledges this incompleteness: [3](#0-2) 

The same gap is flagged inside `PerasVoteDB/Impl.hs`: [4](#0-3) 

The concrete `V1.PerasVote` type **does** carry a `pvSignature` field: [5](#0-4) 

but that signature is never checked by `validatePerasVote`.

The inbound processing pipeline in `processVotes` calls the supplied `validateVote` callback (which resolves to `validatePerasVote`) and, on success, immediately stores the result in the `PerasVoteDB`: [6](#0-5) [7](#0-6) 

Once stored, `implAddVote` calls `updatePerasRoundVoteStates`, which calls `updateCandidateVoteState`, which calls `votesReachQuorum`, and—if the accumulated stake of the forged votes crosses the quorum threshold—calls `forgePerasCert` to produce a `ValidatedPerasCert`: [8](#0-7) [9](#0-8) 

The fraudulent certificate is then used by chain selection to apply a Peras boost to an attacker-chosen block.

---

### Impact Explanation

An unprivileged remote peer can:

1. Enumerate registered pool IDs from the public stake distribution (public on-chain data).
2. Craft `PerasVote` messages with arbitrary `pvVoteVoterId` values matching those pools and any desired `pvVoteBlock` target.
3. Send the batch via the ObjectDiffusion mini-protocol; `processVotes` accepts them because `validatePerasVote` only checks stake-distribution membership.
4. Accumulate enough forged votes to cross the quorum threshold, causing `implAddVote` to forge a `ValidatedPerasCert` boosting an attacker-chosen block.
5. The fraudulent certificate propagates to chain selection, causing honest nodes to prefer a non-canonical chain.

This is a **Critical bypass of Peras voting and certificate checks**: the `ValidatedPerasVote` / `ValidatedPerasCert` types are supposed to be proof that cryptographic verification succeeded, but they can be produced without any signature check.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol is reachable by any peer that can establish a node-to-node connection. The stake distribution is public. No private key material is required. The attacker only needs to know which pool IDs are registered and their approximate stake weights to compute how many forged votes are needed to reach quorum. The attack is therefore executable by any unprivileged network participant.

---

### Recommendation

1. **Implement full cryptographic verification** in `validatePerasVote` for every concrete `BlockSupportsPeras` instance. For `V1.PerasVote`, this means verifying `pvSignature` against the pool's registered VRF/vote-signing key before constructing `ValidatedPerasVote`.
2. **Remove the default implementation** of `validatePerasVote` (or make it `error`/`undefined`) so that any new instance is forced to provide a real check rather than silently inheriting the stub.
3. Resolve the tracked issue (`https://github.com/tweag/cardano-peras/issues/120`) before the Peras vote-diffusion path is enabled on any production network.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Remote peer
  → ObjectDiffusion mini-protocol
  → processVotes (PerasVote.hs:178)
      → validateVote = \vote -> getStakeDistrSTM >>= \sd ->
                                  pure $ validatePerasVote mkPerasParams sd vote
          → validatePerasVote (SupportsPeras.hs:363):
              only checks: Map.lookup (pvVoteVoterId vote) stakeDistr
              ← returns Right (ValidatedPerasVote vote stake)   -- NO SIG CHECK
      → addVote (PerasVoteDB.addVote)
          → implAddVote → updatePerasRoundVoteStates
              → updateCandidateVoteState → votesReachQuorum
                  → forgePerasCert  ← fraudulent cert produced
```

**Concrete steps:**

1. Attacker queries the current stake distribution (public ledger state query).
2. Attacker selects pools whose combined stake exceeds the quorum threshold `τ`.
3. For each selected pool `p_i`, attacker constructs:
   ```
   PerasVote { pvVoteRound = r, pvVoteBlock = attackerBlock,
               pvVoteVoterId = p_i, ... }
   ```
   No valid signature is needed; the `pvSignature` field is present in `V1.PerasVote` but is never checked.
4. Attacker sends the batch to the victim node via the ObjectDiffusion protocol.
5. `processVotes` calls `validatePerasVote` for each vote; all pass because each `p_i` is in the stake distribution.
6. Votes are stored; once cumulative stake ≥ quorum, `forgePerasCert` fires and the fraudulent certificate boosts `attackerBlock` in chain selection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L361-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-236)
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
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-113)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
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
