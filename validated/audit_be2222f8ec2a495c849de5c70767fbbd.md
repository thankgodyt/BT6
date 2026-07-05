### Title
Stub `validatePerasCert` and `validatePerasVote` Accept Arbitrary Peras Votes and Certificates Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance unconditionally accepts any `PerasCert` and accepts any `PerasVote` from a voter present in the stake distribution, without verifying cryptographic signatures, VRF eligibility proofs, or round validity. An unprivileged peer can inject crafted certificates or votes via the object-diffusion mini-protocol, causing honest nodes to accept unauthorized Peras certificates that boost chain weight and distort chain selection.

---

### Finding Description

The `BlockSupportsPeras` instance in `SupportsPeras.hs` is the only instance in the codebase and is therefore the one used in all production code paths. Its `validatePerasCert` implementation accepts every certificate unconditionally:

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
``` [1](#0-0) 

No signature, no round-number bound, no boosted-block ancestry check — every `PerasCert` is wrapped in `Right ValidatedPerasCert` and returned as valid.

Similarly, `validatePerasVote` only checks that the voter's ID appears in the stake distribution map; it does not verify the BLS vote signature or the VRF eligibility proof required for non-persistent committee members:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

Both stubs are reached through the live inbound processing path. `processVotes` in `PerasVote.hs` calls `validatePerasVote mkPerasParams sd vote` and then forwards accepted votes to `addVote`: [3](#0-2) 

The `makePerasVotePoolWriterFromChainDB` function wires this directly into the ChainDB's vote ingestion path used by the object-diffusion mini-protocol: [4](#0-3) 

The `BlockSupportsPeras` instance is explicitly labeled a "degenerate instance for all blks to get things to compile" with no more-specific override present for Cardano blocks: [5](#0-4) 

---

### Impact Explanation

**For `validatePerasCert`:** Any peer can craft a `PerasCert` naming an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The certificate is accepted, stored in the `PerasCertDB`, and assigned a `vpcCertBoost` weight. Because Peras certificates boost chain weight in chain selection, an attacker can make an honest node prefer a non-canonical or attacker-controlled chain by injecting a certificate that boosts a weaker fork. This is a **Critical** consensus safety failure: unauthorized certificate acceptance directly distorts chain selection without requiring any key material.

**For `validatePerasVote`:** Any peer who knows a voter's public key hash (which is public information from the stake distribution) can send votes attributed to that voter for any round and any block, without possessing the voter's private key. Because `updateTargetVoteTally` deduplicates only by `PerasVoteId` (round + voter ID), a single attacker controlling one connection can inject one vote per known voter per round. With enough impersonated voters, the attacker accumulates stake above the quorum threshold, causing `forgePerasCert` to be called and a fraudulent certificate to be stored — again distorting chain selection. [6](#0-5) 

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras votes is reachable by any connected peer. No privileged access, key compromise, or stake majority is required. The attacker only needs to know voter IDs from the public stake distribution (for the vote path) or simply send a well-formed CBOR-encoded `PerasCert` (for the cert path). Both `PerasCert` and `PerasVote` have public `Serialise` instances, making crafting trivial. [7](#0-6) 

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation — verify the aggregate BLS signature over `(electionId, candidate)` against the aggregate public key of the claimed voters, verify each voter's eligibility (persistent membership or VRF proof), and check that `pcCertRound` is within the valid window and `pcCertBoostedBlock` is a known block. The `implVerifyCert` function in `WFALS.hs` shows the correct pattern for the `WFALS` committee type and should be wired into the production `validatePerasCert` path. [8](#0-7) 

2. **`validatePerasVote`**: Implement full vote validation — verify the BLS vote signature and, for non-persistent members, the VRF eligibility proof. The `implVerifyVote` function in `WFALS.hs` provides the correct reference implementation. [9](#0-8) 

3. Remove or gate the degenerate `BlockSupportsPeras` instance so it cannot be used in production contexts where actual Peras validation is required.

---

### Proof of Concept

**Certificate injection (no key material needed):**

```haskell
-- Craft a certificate boosting an attacker-chosen block in an arbitrary round
let craftedCert = PerasCert
      { pcCertRound    = PerasRoundNo 999
      , pcCertBoostedBlock = someWeakForkPoint
      }
-- validatePerasCert accepts it unconditionally
Right validatedCert = validatePerasCert mkPerasParams craftedCert
-- validatedCert is now stored in ChainDB and boosts someWeakForkPoint
```

**Vote injection (only public voter ID needed):**

```haskell
-- For each known voter in the stake distribution:
let craftedVote = PerasVote
      { pvVoteRound   = currentRound
      , pvVoteBlock   = attackerForkPoint
      , pvVoteVoterId = knownVoterId  -- public info, no private key needed
      }
-- validatePerasVote accepts it (signature not checked)
Right validatedVote = validatePerasVote mkPerasParams stakeDistr craftedVote
-- Repeat for enough voters to exceed quorum threshold
-- => fraudulent certificate forged for attackerForkPoint
``` [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L195-203)
```haskell
-- | Lookup the stake of a vote cast by a member of a given stake distribution.
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-422)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}

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
    pvVoteVoterId <- PerasVoterId <$> KeyHash.fromCBOR
    pure $ PerasVote{pvVoteRound, pvVoteBlock, pvVoteVoterId}
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L430-459)
```haskell
updateTargetVoteTally ::
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasTargetVoteTally blk ->
  PerasTargetVoteTally blk
updateTargetVoteTally
  vote
  ptvt@PerasTargetVoteTally
    { ptvtVotes
    , ptvtTarget
    , ptvtTotalStake
    } =
    assert (getPerasVoteTarget vote == ptvtTarget) $ do
      ptvt
        { ptvtVotes = pvaVotes'
        , ptvtTotalStake = pvaTotalStake'
        }
   where
    swapVote =
      Map.insertLookupWithKey
        (\_k old _new -> old)
        (getPerasVoteId vote)

    (pvaVotes', pvaTotalStake')
      -- key WAS NOT present → vote inserted and stake updated
      | (Nothing, votes') <- swapVote vote ptvtVotes =
          (votes', ptvtTotalStake + vpvVoteStake (forgetArrivalTime vote))
      -- key WAS already present → votes and stake unchanged
      | otherwise =
          (ptvtVotes, ptvtTotalStake)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-586)
```haskell
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    -- 3. optionally, their VRF verification keys and outputs (to verify the
    --    aggregate VRF output for non-persistent voters, if any)
    (members, voteVerificationKeys, optionalVRFKeysAndOutputs) <-
      fmap nonEmptyUnzip3 . flip traverse (NEMap.toAscList voters) $ \case
        -- Persistent voter
        (seatIndex, Nothing)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , isPersistentMember seatIndex committee -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              pure
                ( WFALSPersistentMember
                    seatIndex
                    voterStake
                , voterVoteVerificationKey
                , Nothing
                )
          | otherwise ->
              Left (NotAPersistentMember seatIndex)
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
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
                  pure
                    ( WFALSNonPersistentMember
                        seatIndex
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
