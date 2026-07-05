### Title
Degenerate `BlockSupportsPeras` Instance Bypasses All Peras Certificate and Vote Cryptographic Validation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass defines `validatePerasCert` and `validatePerasVote` as the security-critical functions responsible for verifying Peras certificates and votes received from peers. However, the only concrete instance — a degenerate catch-all instance for all block types — implements both functions as stubs that unconditionally accept any input without performing any cryptographic verification. Because this is the only instance in the codebase, the validation functions exist in the interface but are never actually enforced, directly analogous to the external report's pattern of a security function that exists internally but is never invoked.

---

### Finding Description

The `BlockSupportsPeras` typeclass in `SupportsPeras.hs` declares two security-critical methods:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk ->
  PerasVoteStakeDistr ->
  PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The only instance of this typeclass is the degenerate catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
```

`validatePerasCert` unconditionally returns `Right` — no signature, no round number, no boosted-block integrity check of any kind. `validatePerasVote` only checks that the voter's key appears in the stake distribution; it performs no cryptographic signature verification over the vote payload.

Contrast this with the real validation logic that exists for the `WFALS` and `EveryoneVotes` committee schemes in `Committee/WFALS.hs` and `Committee/EveryoneVotes.hs`, which verify aggregate BLS signatures, VRF outputs, and seat-index membership. The typeclass interface was designed to call into that logic, but the degenerate instance bypasses it entirely.

The network-reachable entry paths that call these stub implementations are:

- `processCerts` in `ObjectPool/PerasCert.hs` — called when a batch of `PerasCert` objects arrives from a peer via the object-diffusion mini-protocol. It calls the injected `validateCert` callback, which resolves to `validatePerasCert` from the degenerate instance.
- `processVotes` / `makePerasVotePoolWriterFromChainDB` in `ObjectPool/PerasVote.hs` — called when a batch of `PerasVote` objects arrives from a peer. It calls `validatePerasVote` from the same degenerate instance. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate and vote signature verification enabling unauthorized certificate/vote acceptance.**

An unprivileged peer can craft and send:

1. **Arbitrary Peras certificates** — `validatePerasCert` always returns `Right`, so any certificate for any round and any boosted block is accepted and stored in `PerasCertDB` without any proof that a quorum of committee members actually signed it.
2. **Forged Peras votes attributed to any registered stake pool** — `validatePerasVote` only checks that the claimed voter key appears in the stake distribution; it does not verify the vote's cryptographic signature. Any peer knowing a pool's public key (which is public) can forge votes on its behalf.

Once forged votes accumulate to quorum in `votesReachQuorum`, `forgePerasCert` is called to produce a `ValidatedPerasCert` that carries a chain-selection boost (`vpcCertBoost = perasWeight params`). This boost is the core Peras finality mechanism: it causes honest nodes to prefer the boosted chain over competing chains. An attacker who can inject forged certificates can therefore steer chain selection toward an attacker-chosen block, constituting a consensus safety failure. [4](#0-3) 

---

### Likelihood Explanation

The object-diffusion mini-protocol is a standard peer-to-peer channel. Any node that connects to a Peras-enabled node can submit `PerasCert` and `PerasVote` objects. No privileged keys, no stake, and no prior relationship are required. The degenerate instance is the only instance in the entire codebase, so there is no code path through which real validation is ever invoked. The attack requires only the ability to open a network connection and send well-formed (but cryptographically invalid) CBOR-encoded objects.

---

### Recommendation

Replace the degenerate stub implementations with real cryptographic validation before the Peras object-diffusion layer is enabled in production:

1. **`validatePerasCert`** must verify the aggregate BLS signature over the certificate's `(roundNo, boostedBlock)` payload against the committee's aggregate verification key, following the pattern in `Committee/EveryoneVotes.hs` (`implVerifyCert`) and `Committee/WFALS.hs`.
2. **`validatePerasVote`** must verify the individual vote's cryptographic signature (using `checkVoteSignature` from `Committee/WFALS.hs` or the equivalent) in addition to the stake-distribution lookup.
3. Until real implementations are in place, the object-diffusion handlers for Peras objects should be gated behind a feature flag that is disabled by default, preventing the stub validation from being reachable from the network. [5](#0-4) [6](#0-5) 

---

### Proof of Concept

**Attacker-controlled entry path:**

```
peer connects via object-diffusion mini-protocol
  → sends [PerasCert { pcCertRound = r, pcCertBoostedBlock = b }]
  → processCerts (PerasCert.hs:164) calls validateCert
  → validateCert = validatePerasCert (SupportsPeras.hs:353)
  → returns Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
  → cert stored in PerasCertDB with full boost weight
  → chain selection applies boost to block b
```

**Forged vote path:**

```
peer sends [PerasVote { pvVoteRound = r, pvVoteBlock = b, pvVoteVoterId = anyRegisteredPool }]
  → processVotes (PerasVote.hs:178) calls validateVote
  → validatePerasVote checks only lookupPerasVoteStake (SupportsPeras.hs:363)
  → stake lookup succeeds (pool is registered, key is public)
  → vote accepted as ValidatedPerasVote with full stake weight
  → if enough forged votes accumulate → votesReachQuorum → forgePerasCert
  → forged cert stored with boost
```

No private keys, no stake, and no operator access are required. The only prerequisite is a network connection to a node running the Peras object-diffusion layer. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-201)
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
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }

data PerasVoteInboundException
  = forall blk. PerasVoteValidationError [PerasValidationErr blk]

deriving instance Show PerasVoteInboundException

instance Exception PerasVoteInboundException

-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L541-586)
```haskell
                        voterStake
                        vrfOutput
                        nonZeroNumSeats
                    , voterVoteVerificationKey
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)

    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig

    -- Verify VRF outputs for non-persistent voters (if any)
    case catMaybes (NonEmpty.toList optionalVRFKeysAndOutputs) of
      -- No non-persistent voters => no VRF outputs to verify
      [] -> do
        pure ()
      -- Some non-persistent voters => verify their aggregate VRF outputs
      vrfKeysAndOutputs -> do
        let (vrfVerificationKeys, vrfOutputs) =
              munzip
                . NonEmpty.fromList -- safe 'vrfKeysAndOutputs' /= []
                $ vrfKeysAndOutputs
        bimap InvalidCertSignature id $
          batchVerifyVRFOutputs
            vrfVerificationKeys
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
            vrfOutputs

    -- Return the list of voters attesting the election winner
    pure members
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-340)
```haskell
implVerifyCert committee = \case
  EveryoneVotesCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    (members, voteVerificationKeys) <-
      fmap munzip . flip traverse (NESet.toAscList voters) $ \case
        seatIndex
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
              let voterVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              case nonZero voterStake of
                Nothing ->
                  Left (PoolHasNoStake seatIndex)
                Just nonZeroVoterStake ->
                  pure
                    ( EveryoneVotesMember
                        seatIndex
                        nonZeroVoterStake
                    , voterVerificationKey
                    )
          | otherwise ->
              Left (MissingSeatIndex seatIndex)
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $ do
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig

    -- Return the list of voters attesting the election winner
    pure members
```
