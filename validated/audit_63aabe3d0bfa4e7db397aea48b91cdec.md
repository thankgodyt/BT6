### Title
Peras `validatePerasCert` and `validatePerasVote` are no-op stubs that accept any certificate or vote from any peer without committee membership or signature verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass instance — the production instance used for all block types — implements `validatePerasCert` as an unconditional `Right` (accepts every certificate) and `validatePerasVote` without any cryptographic or committee-eligibility check. Any unprivileged peer can send a crafted `PerasCert` for an arbitrary block and have it accepted as a valid Peras certificate, receiving the full `perasWeight` boost in chain selection. Similarly, any peer can forge votes attributed to any voter ID present in the stake distribution without possessing that voter's private key.

---

### Finding Description

The `BlockSupportsPeras` instance at lines 320–389 of `SupportsPeras.hs` is the **only** concrete instance in the codebase (via `instance StandardHash blk => BlockSupportsPeras blk`). Both critical validation methods are stubs:

**`validatePerasCert`** (lines 350–358):
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
This unconditionally returns `Right` for **any** `PerasCert`, regardless of its content. No aggregate BLS signature is verified, no committee membership is checked, and no round/slot constraints are enforced.

**`validatePerasVote`** (lines 360–371):
```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```
This only checks that the voter ID appears in the stake distribution. It does **not** verify the vote's cryptographic signature, the VRF eligibility proof for non-persistent committee members, or the round/slot validity. Any peer can forge a vote attributed to any staked pool ID without possessing that pool's private key.

These stubs are called directly in the live inbound-vote processing path. `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB` both pass `validatePerasVote mkPerasParams sd vote` as the `validateVote` callback to `processVotes`, which is the function that handles all votes received from peers over the network. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

**Certificate injection → chain selection manipulation (Critical).**

A `ValidatedPerasCert` carries a `vpcCertBoost = perasWeight params` field. This boost is applied during chain selection to prefer the boosted block over competing candidates. Because `validatePerasCert` accepts any certificate unconditionally, an unprivileged peer can:

1. Construct a `PerasCert` pointing to any block (including one on an adversarial fork).
2. Send it to a target node over the Peras object-diffusion miniprotocol.
3. The node accepts it as a `ValidatedPerasCert` with full boost weight.
4. Chain selection now prefers the adversarial block, causing the honest node to diverge from the canonical chain.

This is a direct analog to the external report: just as any address could call `refundCancelledGame` without having joined the game and drain tokens, any peer can submit a certificate for a block it never legitimately won a Peras election for, and the node will apply the boost unconditionally.

**Vote forgery → fake quorum → fake certificate (Critical).**

Because `validatePerasVote` does not verify signatures or VRF proofs, an attacker who knows any staked pool ID (public information from the ledger) can forge votes attributed to that pool. By submitting enough forged votes across multiple pool IDs to exceed the quorum threshold, the attacker can cause the `PerasVoteDB` to forge a `ValidatedPerasCert` for an arbitrary block, again manipulating chain selection. [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

**High.** The attack requires only a network connection to the target node. The Peras object-diffusion miniprotocol is reachable by any peer. No privileged keys, stake, or prior knowledge beyond public ledger data (pool IDs and their stake) is required. The `processVotes` path is exercised for every batch of inbound votes, and `validatePerasCert` is called on every inbound certificate. The stubs are the **only** production implementations; there is no feature flag or era gate that disables them. [6](#0-5) 

---

### Recommendation

1. **`validatePerasCert`**: Implement full aggregate BLS signature verification against the committee's public keys for the relevant round, verify that the claimed voters form a valid quorum, and check round/slot constraints before returning `Right`.

2. **`validatePerasVote`**: In addition to the stake-distribution lookup, verify the vote's cryptographic signature using the voter's public key, and for non-persistent members verify the VRF eligibility proof against the epoch nonce and election ID. This mirrors the logic already present in `implVerifyVote` in `Committee/WFALS.hs` and `Committee/EveryoneVotes.hs`.

3. The `implAddVote` TODO (line 172–173 of `PerasVoteDB/Impl.hs`) should be resolved in tandem, as it acknowledges that non-trivial validation logic is still missing at the DB layer. [7](#0-6) [8](#0-7) 

---

### Proof of Concept

**Certificate injection path:**

```
Attacker peer                          Target node
     |                                      |
     |  -- PerasCert { round=R,             |
     |       block=<adversarial_hash> } --> |
     |                                      |
     |                          validatePerasCert params cert
     |                          = Right (ValidatedPerasCert cert (perasWeight params))
     |                                      |
     |                          Chain selection applies boost to
     |                          <adversarial_hash>, node diverges
     |                          from canonical chain
```

**Vote forgery path (using public pool IDs from ledger):**

```
Attacker peer                          Target node
     |                                      |
     |  -- [PerasVote { round=R,            |
     |       block=<adversarial_hash>,      |
     |       voterId=<any_staked_pool> }]-->|
     |                                      |
     |                          validatePerasVote: lookupPerasVoteStake succeeds
     |                          (no signature check)
     |                          => ValidatedPerasVote with full stake weight
     |                                      |
     |  (repeat for enough pool IDs         |
     |   to exceed quorum threshold)        |
     |                                      |
     |                          PerasVoteDB forges ValidatedPerasCert
     |                          for <adversarial_hash>
     |                          Chain selection boosted toward adversarial block
```

The attacker-controlled entry point is the Peras object-diffusion miniprotocol handler, which calls `processVotes` → `validatePerasVote` (stub) → `addVote` for votes, and the certificate diffusion path which calls `validatePerasCert` (stub) for certificates. [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L91-148)
```haskell
-- 'ChainDB' and thus properly handles the produced certs.
makePerasVotePoolWriterFromVoteDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since it is during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  PerasVoteDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-193)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L326-392)
```haskell
-- | Verify a vote cast by a committee member in a given election
implVerifyVote ::
  forall crypto.
  ( CryptoSupportsVoteSigning crypto
  , CryptoSupportsVRF crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Vote crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (EligibilityWitness crypto WFALS)
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
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
        let voterVRFVerificationKey =
              getVRFVerificationKey (Proxy @crypto) voterPublicKey
        let vrfContext =
              VRFVerifyContext voterVRFVerificationKey vrfOutput
        void $ bimap InvalidVoterEligibilityProof id $ do
          evalVRF
            vrfContext
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
        let numSeats =
              localSortitionNumSeats
                (nonPersistentCommitteeSize committee)
                (totalNonPersistentStake committee)
                voterStake
                (normalizeVRFOutput vrfOutput)
        case nonZero numSeats of
          Nothing ->
            Left (ZeroNonPersistentSeats seatIndex)
          Just nonZeroNumSeats ->
            pure $
              WFALSNonPersistentMember
                seatIndex
                voterStake
                vrfOutput
                nonZeroNumSeats
    | otherwise ->
        Left (NotANonPersistentMember seatIndex)
```
