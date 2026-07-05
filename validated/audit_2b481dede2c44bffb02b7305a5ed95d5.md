### Title
Missing Cryptographic Signature Verification in `validatePerasVote` Allows Unprivileged Peer to Pre-empt Legitimate Voter Slots and Corrupt Peras Quorum — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` implementation performs no cryptographic signature check. It accepts any `PerasVote` whose `pvVoteVoterId` (a public key hash) appears in the stake distribution, regardless of whether the submitter controls the corresponding private key. Because the `PerasVoteDB` deduplicates votes by `PerasVoteId = (roundNo, voterId)` and silently discards later arrivals for the same key, an unprivileged peer can pre-occupy every eligible voter's slot for any round by submitting unsigned fake votes before the legitimate voters do. The legitimate votes are then silently dropped, and the attacker's votes — which can target any block — are counted with the legitimate voters' stake weights, corrupting Peras quorum and certificate forging.

---

### Finding Description

**Structural analog to the external report:**
The Salty DAO bug allowed an attacker to pre-occupy the `ballotName + "_confirm"` namespace key, blocking a legitimate two-step proposal because the guard `openBallotsByName[ballotName + "_confirm"] == 0` fired on the attacker's entry. The analog here is: the `PerasVoteDB` deduplication guard fires on `PerasVoteId = (roundNo, voterId)`, and an attacker can pre-occupy that key for any legitimate voter because `validatePerasVote` does not verify that the submitter owns the voter's private key.

**Root cause — degenerate `validatePerasVote` instance:**

The only deployed `BlockSupportsPeras` instance is the catch-all degenerate one:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  data PerasVote blk = PerasVote
    { pvVoteRound   :: PerasRoundNo
    , pvVoteBlock   :: Point blk
    , pvVoteVoterId :: PerasVoterId   -- just a KeyHash; no signature field
    }
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [1](#0-0) 

The `PerasVote` record in this instance carries no `pvSignature` field at all. Validation succeeds for any vote whose `pvVoteVoterId` (a `KeyHash`, i.e. a hash of a public key) is present in the stake distribution. The stake distribution is public on-chain data.

**Deduplication gate in `implAddVote`:**

```haskell
addOrIgnoreVote pvds voteId
  -- Vote is already in the DB => ignore it
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  -- New vote => try to add it to the DB
  | otherwise = tryAddVote pvds voteId
``` [2](#0-1) 

Once a `PerasVoteId = (roundNo, voterId)` is present in `pvdsVoteIds`, any subsequent vote with the same ID is silently discarded as `PerasVoteAlreadyInDB`. There is no check that the first-arriving vote was legitimately signed.

**Network-facing entry path — `processVotes`:**

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb =
          filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  ...
  ([], validatedVotes) ->
    mapM_ (addVote . WithArrivalTime now) validatedVotes
``` [3](#0-2) 

This function is wired directly into the production `ObjectPoolWriter` used by the Peras vote object-diffusion mini-protocol:

```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          (\vote -> getStakeDistrSTM >>= \sd ->
              pure $ validatePerasVote mkPerasParams sd vote)
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    ...
    }
``` [4](#0-3) 

Any peer that connects to the node can submit `PerasVote` messages through this path.

**Contrast with the real vote type:**

The concrete `PerasVote` in `Vote/V1.hs` carries a `pvSignature :: VoteSignature PerasBLSCrypto` and a `pvEligibilityProof`, which are the fields that would prevent this attack. The degenerate instance used in production omits both. [5](#0-4) 

---

### Impact Explanation

An attacker who submits fake votes early in a Peras round — before legitimate committee members do — pre-occupies every `(roundNo, voterId)` slot they target. The legitimate votes arrive later and are silently dropped as duplicates. The attacker's votes, which can target any block point (including a non-canonical or adversarial block), are counted with the full stake weight of the impersonated voters. If the attacker targets enough stake to exceed the quorum threshold, a `ValidatedPerasCert` is forged for the adversarial block, boosting it in chain selection. This constitutes:

- **Bypass of Peras voting checks** enabling unauthorized vote acceptance (Critical per scope).
- **Chain selection corruption**: a certificate forged for an adversarial block adds `perasWeight` to that block's chain weight, potentially causing honest nodes to prefer a non-canonical chain. [6](#0-5) 

---

### Likelihood Explanation

- The stake distribution (`PerasVoteStakeDistr`) is public on-chain data; any peer can enumerate all eligible `PerasVoterId` values.
- The `PerasVote` data type in the degenerate instance has no signature field, so crafting a fake vote requires only knowing the target voter's key hash — no private key material.
- The attack requires only a standard peer connection; no special privileges, no stake, no key compromise.
- The attacker must submit fake votes before legitimate voters in each round, but Peras rounds are time-bounded and the attacker can act at round start.

---

### Recommendation

1. **Immediate**: Gate `processVotes` on a round-eligibility and signature check before inserting into the DB. The `validatePerasVote` method in the `BlockSupportsPeras` class is the correct place; it must verify the BLS signature (as already implemented in `PerasBLSCrypto`) and the eligibility proof before returning `Right`.

2. **Structural**: Replace the degenerate catch-all `BlockSupportsPeras` instance with a proper per-era instance that includes a `pvSignature` field in `PerasVote` and performs full validation, as already designed in `Vote/V1.hs`.

3. **Deduplication ordering**: Even after adding signature verification, consider whether a later-arriving *valid* vote with the same `(roundNo, voterId)` should replace an earlier one, or whether the first-seen policy is intentional. If first-seen, ensure the first-seen vote is always the legitimate one by verifying it before insertion. [7](#0-6) 

---

### Proof of Concept

```
Setup:
  - Node N running with the degenerate BlockSupportsPeras instance
  - Stake distribution S contains voter V with key hash KH_V and stake weight W_V
  - Peras round R begins

Attack:
  1. Attacker A connects to node N as a peer via the Peras vote mini-protocol.
  2. A constructs PerasVote { pvVoteRound = R, pvVoteBlock = adversarialBlock, pvVoteVoterId = KH_V }
     (no signature needed; the degenerate PerasVote record has no signature field)
  3. A sends this vote to N via opwAddObjects.
  4. processVotes calls validatePerasVote mkPerasParams S fakeVote.
     validatePerasVote finds KH_V in S, returns Right (ValidatedPerasVote { vpvVoteStake = W_V }).
  5. The vote is inserted into PerasVoteDB with PerasVoteId = (R, KH_V).
  6. Legitimate voter V later sends their real vote for round R targeting canonicalBlock.
  7. processVotes filters it out: Set.member (R, KH_V) alreadyInDb == True → silently dropped.
  8. A repeats for enough voters to exceed the quorum threshold.
  9. A certificate is forged for adversarialBlock with quorum stake, boosting it in chain selection.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-246)
```haskell
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

    pure
      ( addPerasVoteRes
      , PerasVoteDbState
          { pvdsVoteIds = pvsVoteIds'
          , pvdsRoundVoteStates = pvsRoundVoteStates'
          , pvdsVotesByTicket = pvsVotesByTicket'
          , pvdsLastTicketNo = pvsLastTicketNo'
          }
      )
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L391-400)
```haskell
    { prvsState =
      Right
        Quorum
          { excessVotes = 0 -- just reached quorum
          , winnerState = PerasTargetVoteWinner _ cert
          }
    } ->
      Just cert
  _ ->
    Nothing
```
