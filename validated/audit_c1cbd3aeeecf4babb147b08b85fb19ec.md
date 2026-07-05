### Title
Peras Certificate Validation Unconditionally Accepts Any Peer-Supplied Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or committee-membership verification. This stub is wired directly into the production network-facing certificate ingestion pipeline. An unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and arbitrary boosted-block hash; the node will accept it, store it in the `PerasCertDB`, and apply its weight boost during chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for all inbound Peras certificates. The catch-all default instance (which is the only instance present in the repository) is:

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

No check is performed on:
- the aggregate BLS signature over the election identifier and boosted block,
- committee membership or seat eligibility of any voter listed in the certificate,
- VRF proofs for non-persistent voters,
- quorum threshold (total stake of signers ≥ 3/4),
- round-number plausibility, or
- whether the boosted block actually exists on the node's chain.

This stub is consumed directly by both production certificate-pool writers:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass, stores them via `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never taken. Every certificate from every peer is stored and later used to boost chain selection.

The analogy to the KintoWallet KYC bypass is exact: just as `_validateSignature()` checked only `owner[0]`'s KYC while ignoring all other signers, `validatePerasCert` here checks **none** of the required credentials of any signer in the certificate — the entire multi-party credential check is absent.

The full certificate structure that should be verified (aggregate BLS signature + per-voter VRF proofs) is defined and implemented in `implVerifyCert` for both `WFALS` and `EveryoneVotes` committee schemes: [5](#0-4) [6](#0-5) 

Those implementations are never called from the production ingestion path.

---

### Impact Explanation

A `ValidatedPerasCert` carrying an attacker-chosen `vpcCertBoost` (equal to `perasWeight params`, currently `PerasWeight 15`) is inserted into the `PerasCertDB` and subsequently reflected in the `PerasWeightSnapshot`. Chain selection adds this boost to the weight of the attacker-specified block:

```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
``` [7](#0-6) 

An attacker can therefore:
1. Forge a certificate for any block hash and any round number.
2. Cause an honest node to prefer an adversarial chain over the canonical chain (chain-selection manipulation).
3. Repeat across rounds to accumulate unbounded artificial weight, permanently biasing chain selection.

This is a **Critical** bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The attack requires only a TCP connection to the node's ObjectDiffusion endpoint. No stake, no keys, no prior authentication. The attacker sends a well-formed CBOR-encoded `PerasCert` with an arbitrary `pcBoostedBlock` and `pcRoundNo`. The node accepts it unconditionally. The attack is trivially scriptable and repeatable.

---

### Recommendation

Replace the stub `validatePerasCert` with a call to `verifyCert` from the appropriate `CryptoSupportsVotingCommittee` instance (e.g., `implVerifyCert` for `WFALS`), and additionally verify:
- the aggregate BLS signature over `(electionId, candidate)`,
- VRF proofs for all non-persistent voters,
- that the total vote weight of verified signers meets `perasQuorumStakeThreshold`,
- that the round number is within the valid window relative to the current tip.

The `PerasCertCompatibleWithVotingCommittee` conversion layer (`fromPerasCert`) and `verifyCert` are already implemented and ready to be wired in. [8](#0-7) 

---

### Proof of Concept

1. Connect to a node's ObjectDiffusion port.
2. Send a `PerasCert` (CBOR-encoded per `V1.PerasCert`) with:
   - `pcRoundNo` = any round number not yet in the `PerasCertDB`,
   - `pcBoostedBlock` = hash of any block the attacker wishes to boost,
   - `pcVoters` = empty or minimal voter map,
   - `pcSignature` = zeroed/random bytes.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
4. The cert is stored via `addCert` with `vpcCertBoost = PerasWeight 15`.
5. On the next chain-selection pass, `weightBoostOfPoint` returns `PerasWeight 15` for the attacker's chosen block, causing the node to prefer the adversarial chain over the honest chain by 15 weight units per forged certificate.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L293-340)
```haskell
implVerifyCert ::
  forall crypto.
  CryptoSupportsAggregateVoteSigning crypto =>
  VotingCommittee crypto EveryoneVotes ->
  Cert crypto EveryoneVotes ->
  Either
    (VotingCommitteeError crypto EveryoneVotes)
    (NE [EligibilityWitness crypto EveryoneVotes])
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L313-317)
```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Committee.hs (L148-156)
```haskell
  fromPerasCert = \case
    V1.PerasCert electionId candidate voters sig -> do
      let voters' = fromPerasCertVoters voters
      pure $
        WFALSCert
          electionId
          candidate
          voters'
          sig
```
