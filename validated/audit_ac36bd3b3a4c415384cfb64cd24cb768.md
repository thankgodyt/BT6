### Title
Unconditional Peras Certificate Acceptance — Stub `validatePerasCert` Bypasses All Cryptographic Checks on Inbound Peer Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance provides a stub `validatePerasCert` that unconditionally returns `Right` (success) for every inbound Peras certificate, performing zero cryptographic or structural checks. This stub is wired directly into the live network ingest path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can send a crafted `PerasCert` for an arbitrary round and arbitrary block; it will be accepted, stored in the `PerasCertDB`, and used to boost chain-selection weight — without any BLS aggregate-signature verification, VRF eligibility proof, quorum check, or round-number validation.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for all inbound Peras certificates. The sole production instance (the catch-all `instance StandardHash blk => BlockSupportsPeras blk`) implements this gate as a no-op stub:

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

This stub is called directly from the live network ingest pipeline. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`, which applies it to every certificate received from a remote peer:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then stores every certificate that passes "validation" (i.e., every certificate) into the ChainDB: [3](#0-2) 

The checks that are entirely absent from the stub include:

- **BLS aggregate signature verification** — `verifyAggregateVoteSignature` from `CryptoSupportsAggregateVoteSigning` is never called.
- **VRF eligibility proof verification** — `batchVerifyVRFOutputs` / `linearizeAndVerifyVRFs` are never called.
- **Quorum threshold check** — the number of voters and their combined stake are never validated.
- **Round-number and boosted-block plausibility** — no check against the current chain state.

The full cryptographic pipeline that *does* exist (in `WFALS.hs` `implVerifyCert` and `EveryoneVotes.hs` `implVerifyCert`) is completely bypassed because the stub never delegates to it. [4](#0-3) 

---

### Impact Explanation

A stored `ValidatedPerasCert` contributes a `vpcCertBoost` weight to chain selection. An attacker who can inject an accepted certificate for a round pointing to an attacker-controlled block causes honest nodes to assign extra chain-selection weight to that block, potentially making the node prefer a non-canonical or adversary-controlled chain. Because the stub accepts *any* `PerasCert` regardless of content, an attacker can:

1. Forge a certificate for any past or future round pointing to any block hash.
2. Have it accepted and stored by every node running this code.
3. Influence chain selection in favor of an arbitrary block, bypassing the entire Peras voting and quorum mechanism.

This constitutes a **bypass of Peras certificate/vote verification checks** enabling unauthorized certificate acceptance, matching the Critical/High impact scope.

---

### Likelihood Explanation

The vulnerability is reachable by any peer that can connect to the node's ObjectDiffusion mini-protocol endpoint — no special privileges, no key material, no stake required. The `processCerts` path is exercised whenever a peer sends `PerasCert` objects. The stub is the *only* production implementation of `validatePerasCert`; there is no fallback or secondary check. Likelihood is **High** once Peras is active on a network running this code.

---

### Recommendation

Replace the stub with a real implementation that:

1. Verifies the BLS aggregate vote signature via `verifyAggregateVoteSignature` using the committee's aggregate verification key.
2. Verifies VRF eligibility proofs for non-persistent voters via `batchVerifyVRFOutputs`.
3. Checks that the number of voters and their combined stake meet the quorum threshold.
4. Validates the round number against the current chain state and the boosted block against known blocks.

The cryptographic primitives for all of these checks already exist in `Ouroboros.Consensus.Committee.WFALS` (`implVerifyCert`) and `Ouroboros.Consensus.Committee.EveryoneVotes` (`implVerifyCert`). The stub should be replaced with a dispatch to the appropriate committee-scheme verifier, or the catch-all instance should be removed in favour of a concrete per-block-type instance that wires in the real verifier.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to a target node's ObjectDiffusion endpoint.
2. Craft a `PerasCert blk` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block the attacker wishes to boost (e.g., a minority-chain tip).
3. Send the certificate via the `ObjectPool` diffusion protocol.
4. Observe via the node's chain-selection logs that the certificate is accepted (`PerasCertAlreadyInDB` is not returned, no `PerasCertValidationError` is thrown) and stored.
5. Observe that the boosted block receives `perasWeight` additional chain-selection weight, causing the node to prefer the attacker-chosen chain tip.

The stub at lines 353–358 of `SupportsPeras.hs` is the necessary and sufficient vulnerable step: it returns `Right` unconditionally, so step 3 always succeeds regardless of certificate content. [5](#0-4) [6](#0-5)

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
