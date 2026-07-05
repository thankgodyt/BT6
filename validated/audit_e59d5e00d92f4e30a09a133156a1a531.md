### Title
Default `BlockSupportsPeras` Instance Skips All Cryptographic Verification for Peras Votes and Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance unconditionally accepts any inbound Peras certificate (`validatePerasCert` always returns `Right`) and accepts any vote without verifying its cryptographic signature (`validatePerasVote` only checks stake-distribution membership). The parallel implementations in `WFALS` and `EveryoneVotes` both perform full cryptographic verification. Because `processCerts` and `processVotes` in the object-diffusion layer call these methods on every peer-supplied object, an unprivileged peer can inject arbitrary crafted certificates and votes that pass "validation" and are stored in the ChainDB, bypassing the Peras certificate/vote authorization entirely.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` and `validatePerasVote` as the mandatory gatekeepers for inbound Peras objects. Two concrete committee implementations perform full verification:

- `WFALS.implVerifyCert` verifies the aggregate BLS vote signature **and** batch-verifies all non-persistent voters' VRF outputs. [1](#0-0) 

- `EveryoneVotes.implVerifyCert` verifies the aggregate BLS vote signature against all listed voters. [2](#0-1) 

- `WFALS.implVerifyVote` verifies both the individual vote signature and the VRF eligibility proof. [3](#0-2) 

However, the universal default instance — which applies to **all** block types including Cardano blocks, because no more-specific instance exists — implements these methods as stubs:

```haskell
-- TODO: perform actual validation against all possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
```

`validatePerasCert` unconditionally returns `Right` — no signature, no round-number bounds, no boosted-block validity check. `validatePerasVote` only checks that the voter ID appears in the stake distribution; it never calls `verifyVoteSignature` or `evalVRF`. [4](#0-3) 

These methods are called directly on every peer-supplied object in the production object-diffusion inbound path:

```haskell
opwAddObjects = \certs ->
  processCerts systemTime (ChainDB.getPerasCertIds chainDB)
    (validatePerasCert mkPerasParams)   -- ← always Right
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [5](#0-4) 

```haskell
opwAddObjects = \votes ->
  processVotes systemTime (ChainDB.getPerasVoteIds chainDB)
    (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
    (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
    votes
``` [6](#0-5) 

`processCerts` and `processVotes` add every object that passes validation to the ChainDB; a failure only occurs if `validateCert`/`validateVote` returns `Left`. [7](#0-6) 

---

### Impact Explanation

A Peras certificate stored in the ChainDB boosts the weight of the block it references during chain selection. Because `validatePerasCert` always returns `Right`, an attacker can craft a certificate for any block point and any round number, have it accepted by any peer running this code, and cause that peer to assign an illegitimate boost to an attacker-chosen block. This is a **bypass of Peras certificate authorization** that can make an honest node prefer a non-canonical or adversarially-chosen chain. Similarly, forged votes with any voter ID present in the stake distribution are accepted without signature verification, allowing an attacker to manufacture quorum and trigger spurious certificate generation inside the `PerasVoteDB`. [8](#0-7) 

---

### Likelihood Explanation

The entry path is a standard peer-to-peer connection: any node that connects via the object-diffusion mini-protocol can send `PerasCert` or `PerasVote` objects. No keys, stake, or privileged access are required. The only prerequisite is that the target node has Peras support compiled in and the object-diffusion handlers active, which is the case for any node built from this codebase with Peras enabled.

---

### Recommendation

Replace the stub implementations with real cryptographic verification before enabling Peras on any network. Specifically:

1. `validatePerasCert` must verify the aggregate BLS signature over the election ID and candidate, and verify VRF outputs for non-persistent voters, mirroring `WFALS.implVerifyCert` / `EveryoneVotes.implVerifyCert`.
2. `validatePerasVote` must call `verifyVoteSignature` (and `evalVRF` for non-persistent voters) before accepting a vote, mirroring `WFALS.implVerifyVote`.

Until real implementations exist, the object-diffusion inbound handlers should refuse all inbound Peras objects (return a hard error rather than delegating to the stub) so that the stub cannot be reached from the network. [4](#0-3) 

---

### Proof of Concept

1. Connect to a target node as a peer via the object-diffusion protocol.
2. Construct a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block on a minority fork.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{...}` unconditionally.
4. The certificate is stored in `PerasCertDB` via `ChainDB.addPerasCertAsync`.
5. Chain selection now sees a certificate boost for the attacker-chosen block, potentially causing the node to switch to or prefer the minority fork.

For votes: construct a `PerasVote` with `pvVoteVoterId` set to any pool ID present in the current stake distribution. `validatePerasVote` returns `Right` (stake lookup succeeds, no signature check). Enough such forged votes trigger `updatePerasRoundVoteStates` to reach quorum and forge a certificate internally, amplifying the attack without the attacker needing to forge a certificate directly. [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-390)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L550-583)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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
