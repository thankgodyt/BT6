### Title
Peras Certificate and Vote Signature Verification Bypass via Stub `validatePerasCert`/`validatePerasVote` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance provides stub implementations of `validatePerasCert` and `validatePerasVote` that bypass all cryptographic verification. `validatePerasCert` accepts every inbound Peras certificate unconditionally, and `validatePerasVote` only checks stake existence without verifying the vote signature or VRF eligibility proof. These stubs are the **only** implementations in the codebase and are wired directly into the production inbound-object diffusion paths for Peras votes and certificates.

---

### Finding Description

The `BlockSupportsPeras` class defines two critical validation methods:

1. `validatePerasCert` — should verify the aggregate BLS signature, VRF eligibility proofs for non-persistent voters, committee membership, and the election ID / candidate block.
2. `validatePerasVote` — should verify the vote signature and VRF eligibility proof.

The universal stub instance is declared as:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

Its `validatePerasCert` always returns `Right` — accepting every certificate unconditionally:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

Its `validatePerasVote` only checks whether the claimed voter ID has stake in the distribution, without verifying the vote signature:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

Critically, the stub `PerasVote` data type carries no signature field at all — only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — so there is structurally no credential to bind the claimed voter identity to the vote: [4](#0-3) 

A `grep` for `instance BlockSupportsPeras` returns **no other instances**, confirming this stub is the sole implementation for all block types.

**This stub is wired into production inbound-object diffusion.** `makePerasCertPoolWriterFromCertDB` calls `validatePerasCert mkPerasParams` directly: [5](#0-4) 

And `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote` on every inbound vote: [6](#0-5) 

The correct cryptographic verification logic — aggregate BLS signature verification, per-voter VRF eligibility proof verification, and committee membership checks — exists in `implVerifyVote` and `implVerifyCert` in `WFALS.hs`: [7](#0-6) [8](#0-7) 

But this logic is **not** connected to the production validation path.

**Analog to the external report:** The external report describes a check that verifies a signer exists (`existing_investor_wallet` signed) but does not verify the signer is bound to the target identity (`existing_investor_wallet_identity` → `identity_account`). Here, `validatePerasVote` verifies that a voter ID exists in the stake distribution (credential exists) but does not verify that the vote was signed by the private key corresponding to that voter ID (credential is not bound to the claimed identity). An attacker can claim any voter ID with stake and submit votes without possessing the corresponding signing key.

---

### Impact Explanation

`validatePerasCert` accepts every inbound certificate unconditionally. A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is applied to the certified block during chain selection. An unprivileged peer can therefore forge a certificate for any block — including a non-canonical adversarial fork — and cause honest nodes to apply a Peras weight boost to it, making them prefer the non-canonical chain. This is a bypass of Peras certificate/vote verification checks that enables unauthorized certificate acceptance and chain-selection manipulation.

This maps to the **Critical** allowed impact: *Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance*, and to the **High** allowed impact: *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.*

---

### Likelihood Explanation

Any peer connected to the node via the object-diffusion mini-protocol can send crafted `PerasCert` or `PerasVote` objects. No cryptographic material is required. The only information needed is a valid voter ID (a pool key hash with positive stake), which is public on-chain data. The attack path is direct: craft a `PerasCert` pointing at any block hash, send it over the wire, and it is accepted and stored.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate BLS signature, VRF eligibility proofs for non-persistent voters, committee membership, and the election ID / candidate block — using the existing `implVerifyCert` logic in `WFALS.hs` or `EveryoneVotes.hs`.
2. Replace the stub `validatePerasVote` with a real implementation that verifies the vote signature and VRF eligibility proof — using the existing `implVerifyVote` logic.
3. Add a signature field to the stub `PerasVote` data type, or replace the stub type entirely with the production `V1.PerasVote` type that carries `pvSignature` and `pvEligibilityProof`.
4. Remove the universal `instance StandardHash blk => BlockSupportsPeras blk` stub once proper per-era instances are in place.

---

### Proof of Concept

1. Connect to a node as an unprivileged peer via the Peras object-diffusion mini-protocol.
2. Construct a `PerasCert` with `pcCertRound` set to any round number and `pcCertBoostedBlock` set to the hash of any block on an adversarial fork.
3. Send the certificate. `processVotes`/`processCerts` calls `validatePerasCert mkPerasParams cert`, which unconditionally returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
4. The certificate is stored in the `PerasCertDB` and its `vpcCertBoost` weight is applied to the adversarial block during chain selection.
5. Honest nodes now prefer the adversarial fork over the canonical chain tip, causing a chain-selection divergence without any stake majority or key compromise.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-152)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L327-392)
```haskell
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
