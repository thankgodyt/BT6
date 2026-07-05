### Title
`validatePerasVote` Checks Voter Presence But Not Vote Signature, Enabling Forged-Vote Quorum and Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The degenerate `BlockSupportsPeras` instance's `validatePerasVote` function validates incoming Peras votes by checking only that the claimed voter ID (`pvVoteVoterId`) is present in the stake distribution, but performs no cryptographic signature verification. Because the `PerasVote` data type in this instance carries no signature field, any unprivileged peer can forge votes for any registered pool without possessing that pool's private key. These forged votes are accepted by `processVotes` and stored in the vote database; once enough forged votes accumulate for the same target, `votesReachQuorum` triggers `forgePerasCert`, producing a certificate that boosts a non-canonical block's weight in chain selection.

### Finding Description
The `BlockSupportsPeras` class defines `validatePerasVote` as the method that must authenticate incoming votes. The degenerate instance — the only instance in the codebase and therefore the active production code path — defines `PerasVote` without any signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
```

and validates votes as:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [1](#0-0) 

Only `pvVoteVoterId` is checked against the stake distribution. The actual pool operator's authorization — a cryptographic signature over `(pvVoteRound, pvVoteBlock)` — is never verified. This is the direct structural analog of the EIP-4626 pattern: the "caller" identity (`pvVoteVoterId`) is checked, but the "owner" authorization (the pool's signing key) is not.

This function is called in the production inbound path via `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB` in `ObjectPool/PerasVote.hs`, both of which pass `validatePerasVote mkPerasParams sd vote` to `processVotes`: [2](#0-1) [3](#0-2) 

`processVotes` accepts any vote that passes validation and stores it in the vote database: [4](#0-3) 

Once `votesReachQuorum` detects sufficient accumulated stake, `forgePerasCert` is called, producing a `ValidatedPerasCert` that is added to the ChainDB and used to boost the target block's weight in chain selection: [5](#0-4) 

Note: the concrete `Peras.Vote.V1.PerasVote` type already carries a `pvSignature :: VoteSignature PerasBLSCrypto` field, confirming that signature verification is the intended design but is absent from the active instance: [6](#0-5) 

### Impact Explanation
An unprivileged peer can forge votes for every pool in the public stake distribution without any private key material. By sending forged votes for a non-canonical block, the attacker causes an honest node to reach quorum, forge a certificate, and boost the non-canonical block's chain-selection weight. This can make the node prefer a non-canonical chain over the canonical one — a **High** chain-selection manipulation: an unprivileged peer causes an honest node to prefer a less-secure chain beyond the intended Peras security assumptions.

### Likelihood Explanation
The stake distribution is public. The `PerasVote` wire format is serialized without a signature field (lines 411–420 of `SupportsPeras.hs`), so any peer can construct syntactically valid votes for any pool. The attack requires no privileged access, no key compromise, and no stake majority — only the ability to send messages to the target node via the Peras vote diffusion mini-protocol (`ObjectPool/PerasVote.hs`). [7](#0-6) 

### Recommendation
Add a cryptographic signature field to the `PerasVote` data type (as already done in `Peras.Vote.V1.PerasVote`) and implement signature verification in `validatePerasVote`. The verification must check the BLS signature against the registered public key for the seat index corresponding to `pvVoteVoterId` in the stake distribution, covering at minimum `(pvVoteRound, pvVoteBlock)`. The `implVerifyVote` functions in `Committee/EveryoneVotes.hs` and `Committee/WFALS.hs` demonstrate the correct pattern: [8](#0-7) 

### Proof of Concept
1. Read the current `PerasVoteStakeDistr` from the node (public, available via state-query).
2. For each `PerasVoterId` in the distribution, construct a `PerasVote` with:
   - `pvVoteRound` = current Peras round
   - `pvVoteBlock` = point of a non-canonical block to boost
   - `pvVoteVoterId` = the target pool's ID
3. Send the forged votes to the target node via the Peras vote diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote`, which accepts each vote because `pvVoteVoterId` is present in the stake distribution — no signature is checked.
5. `votesReachQuorum` detects quorum; `forgePerasCert` produces a `ValidatedPerasCert` for the non-canonical block.
6. The certificate is added to the ChainDB with the full `perasWeight` boost, causing chain selection to prefer the non-canonical chain.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L411-420)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasVote blk) where
  encode PerasVote{pvVoteRound, pvVoteBlock, pvVoteVoterId} =
    encodeListLen 3
      <> encode pvVoteRound
      <> encode pvVoteBlock
      <> KeyHash.toCBOR (unPerasVoterId pvVoteVoterId)
  decode = do
    decodeListLenOf 3
    pvVoteRound <- decode
    pvVoteBlock <- decode
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L104-113)
```haskell
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
