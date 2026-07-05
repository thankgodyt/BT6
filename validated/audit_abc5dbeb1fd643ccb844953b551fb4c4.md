### Title
Peras Certificate Validation Completely Bypassed in `validatePerasCert` Stub — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance used for all block types in production implements `validatePerasCert` as a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Any unprivileged peer can send a crafted `PerasCert` over the Peras certificate diffusion mini-protocol, have it accepted as valid, stored in the certificate database, and used to boost an arbitrary block during chain selection — bypassing the entire Peras certificate authorization mechanism.

---

### Finding Description

**Root cause.** The catch-all instance at line 320 of `SupportsPeras.hs` is explicitly annotated as a temporary placeholder ("TODO: degenerate instance for all blks to get things to compile") and provides the following implementation of `validatePerasCert`:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No field of `cert` is inspected. No signature is verified. No round-number bounds are checked. No boosted-block hash is authenticated. The function always succeeds. [1](#0-0) 

**Production call path.** `validatePerasCert` is wired directly into the live certificate ingestion pipeline in two places:

1. `makePerasCertPoolWriterFromCertDB` — passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`.
2. `makePerasCertPoolWriterFromChainDB` — does the same, feeding accepted certificates into `ChainDB.addPerasCertAsync`. [2](#0-1) 

`processCerts` calls the supplied validator on every inbound certificate and, if all return `Right`, stores them via `addCert`. Because the stub always returns `Right`, every certificate from every peer is stored unconditionally. [3](#0-2) 

**Exploit flow.**

1. Attacker connects to a victim node as a standard peer.
2. Attacker sends a crafted `PerasCert` with an arbitrary `pcCertRound` and an attacker-chosen `pcCertBoostedBlock` (e.g., pointing to a weak or adversarial block) via the Peras certificate object-diffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert cert boost)` without any check.
4. The certificate is timestamped and stored in the `PerasCertDB` / `ChainDB`.
5. The stored certificate applies a chain-selection boost (`vpcCertBoost = perasWeight params`) to the attacker-chosen block, potentially causing the victim node to prefer a non-canonical or adversarial chain.

---

### Impact Explanation

**Severity: Critical — Bypass of Peras certificate verification enabling unauthorized certificate acceptance.**

Peras certificates are the mechanism by which the Peras protocol boosts specific blocks during chain selection. A `ValidatedPerasCert` carries a `vpcCertBoost` weight that directly influences which chain a node selects. By injecting a certificate that boosts an arbitrary block, an attacker can cause an honest node to prefer a non-canonical chain, constituting a chain-selection safety failure reachable by an unprivileged peer with no keys, no stake, and no special privileges — only a network connection.

This matches the allowed impact scope: *"Critical. Bypass of … certificate … checks … that enables unauthorized … certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

**High.** The vulnerable code is in the active production ingestion path (`makePerasCertPoolWriterFromChainDB`), not in a test or disabled branch. The catch-all instance is the only `BlockSupportsPeras` instance in the repository for concrete Cardano block types. Any peer participating in the Peras certificate diffusion sub-protocol can trigger this path with a single malformed message. No cryptographic material, stake, or operator access is required.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:

1. Verifies the aggregate BLS signature in `pcSignature` against the claimed voter set and the `(pcRoundNo, pcBoostedBlock)` message.
2. Checks that `pcRoundNo` falls within the currently valid Peras round window.
3. Verifies that each claimed voter in `pcVoters` is a legitimate committee member with sufficient stake for the given round (analogous to `implVerifyCert` in `WFALS.hs` / `EveryoneVotes.hs`).
4. Rejects any certificate that fails any of the above checks with a typed `PerasValidationErr`.

Until the real implementation is ready, the stub should at minimum be gated behind a feature flag or removed from the live diffusion pipeline so that no inbound certificate can be accepted. [4](#0-3) [5](#0-4) 

---

### Proof of Concept

```
Attacker (peer) ──[PerasCert { pcRoundNo=R, pcBoostedBlock=<adversarial_hash> }]──►
  processCerts
    └─ validatePerasCert mkPerasParams cert
         └─ returns Right (ValidatedPerasCert cert boost)   ← no check performed
    └─ addCert (WithArrivalTime now validatedCert)
         └─ ChainDB.addPerasCertAsync chainDB cert
              └─ chain selection applies boost to <adversarial_hash>
                   └─ node may switch to adversarial chain
```

A deterministic reproduction: construct any `PerasCert blk` value with a `pcCertBoostedBlock` pointing to a known-weak block and submit it via the object-diffusion protocol. Observe that `processCerts` stores it without error and that the boosted block gains `perasWeight params` in chain selection, regardless of whether any legitimate committee member ever voted for it. [3](#0-2) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-298)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
