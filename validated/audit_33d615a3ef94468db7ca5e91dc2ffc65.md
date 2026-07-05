### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate Without Cryptographic Verification — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic checks. This stub is wired directly into the production certificate ingest path (`processCerts`). An unprivileged peer can craft a `PerasCert` with a fabricated aggregate BLS signature and arbitrary boosted-block pointer, have it accepted and stored in `PerasCertDB`, and thereby manipulate Peras chain-selection weights on the victim node.

---

### Finding Description

**Root cause — stub validation always succeeds:**

In `SupportsPeras.hs`, the catch-all `BlockSupportsPeras` instance (the only instance currently present) implements `validatePerasCert` as:

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

No aggregate BLS signature is verified, no VRF eligibility proofs are checked, and no committee membership is confirmed. The function accepts every certificate unconditionally.

**Production ingest path uses this stub:**

`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` both pass this stub as the validator to `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, if all pass, stores them via `addCert`: [3](#0-2) 

**What a valid certificate is supposed to prove:**

A `PerasCert` carries an aggregate BLS vote signature over `(roundNo, boostedBlock)` and, for non-persistent voters, individual VRF outputs proving eligibility. The `verifyAggregateVoteSignature` and `batchVerifyVRFOutputs` paths in `WFALS.implVerifyCert` exist precisely to enforce these checks: [4](#0-3) 

None of those checks are invoked by the stub.

**Analog to the external report's vulnerability class:**

The Harpie report describes signed data that omits a nonce, allowing replay/reorder of stale authorizations. Here the signed data is never verified at all — the certificate's aggregate signature field (`pcSignature`) is decoded from the wire but never checked against the claimed voters' keys. The result is the same class of bypass: an attacker-controlled input that should be rejected by a cryptographic check is instead accepted.

---

### Impact Explanation

`PerasCertDB` feeds `getWeightSnapshot`, which is consumed by chain selection to apply Peras boosting weights to candidate chains: [5](#0-4) 

An attacker who injects a fake certificate for round R boosting block B causes the victim node to assign extra Peras weight to B during chain selection. By targeting a block on a minority or adversarial fork, the attacker can make an honest node prefer a non-canonical chain, constituting a **High** chain-selection integrity failure: an unprivileged peer makes an honest node prefer a less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

Any peer connected via the Peras certificate mini-protocol can send a `PerasCert` message. No keys, stake, or privileged access are required. The attacker only needs to construct a well-formed CBOR-encoded `PerasCert` (round number, boosted block pointer, voter bitmap, any bytes as the aggregate signature). The ingest path accepts it immediately.

---

### Recommendation

Replace the stub with a call to the full cryptographic verification path already implemented in `WFALS.implVerifyCert` (or its equivalent for the concrete Cardano block type). Specifically, `validatePerasCert` must:

1. Reconstruct the `VotingCommittee` for the certificate's round from the ledger state (epoch nonce + stake distribution).
2. Call `verifyAggregateVoteSignature` to check the aggregate BLS signature over `(roundNo, boostedBlock)`.
3. Call `batchVerifyVRFOutputs` for any non-persistent voters to verify their eligibility proofs.
4. Confirm that the number of verified seats meets the quorum threshold.

Until this is done, the Peras certificate ingest path must not be exposed to untrusted peers.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the Peras certificate diffusion mini-protocol.
2. Construct a `PerasCert` (CBOR list of 4):
   - `pcRoundNo`: any current or recent Peras round number.
   - `pcBoostedBlock`: a `RealPoint` pointing to a block on an adversarial fork.
   - `pcVoters`: a `PerasCertVoters` bitmap claiming a quorum of seat indices.
   - `pcSignature`: 48 bytes of arbitrary data (the aggregate BLS signature field is never verified).
3. Send the certificate to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally. [6](#0-5) 
5. The certificate is timestamped and stored in `PerasCertDB` via `addCert`.
6. `getWeightSnapshot` now returns a non-zero Peras boost for the adversarial block.
7. Chain selection on the victim node applies this boost, potentially switching to the adversarial fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```
