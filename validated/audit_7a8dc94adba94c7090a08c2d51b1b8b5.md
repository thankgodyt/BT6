### Title
Degenerate `BlockSupportsPeras` Instance Unconditionally Accepts All Peras Certificates and Votes Without Cryptographic Validation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance, declared for all `StandardHash blk` block types, implements `validatePerasCert` and `validatePerasVote` as stubs that unconditionally return `Right` without performing any cryptographic or structural validation. When Peras is active, a malicious peer can submit crafted certificates boosting arbitrary blocks, bypassing the quorum threshold and aggregate BLS signature requirements that protect chain selection integrity.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the degenerate `BlockSupportsPeras` instance is declared for all `StandardHash blk` block types as a catch-all default:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

The `validatePerasCert` method is supposed to verify the aggregate BLS signature over the certificate's `(roundNo, boostedBlock)` payload against the committee's public keys, and confirm that the quorum threshold is met. Instead, it returns `Right` for every input unconditionally.

The downstream consumer is `processCerts` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  ...
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validateCert` is sourced from the `BlockSupportsPeras` instance and the degenerate instance always returns `Right`, the `(errs, _)` branch is never taken. Every certificate received from a peer is timestamped and inserted into the `PerasCertDB` without any signature or quorum check.

The concrete certificate format (`PerasCert` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs`) carries a `pcSignature :: AggregateVoteSignature PerasBLSCrypto` field that is never verified by this path. [3](#0-2) 

The correct validation logic exists in `implVerifyCert` for the `WFALS` committee scheme in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs` (lines 484–586), which verifies the aggregate BLS signature and VRF outputs for non-persistent voters. That logic is never reached via the degenerate instance. [4](#0-3) 

---

### Impact Explanation

Peras certificates boost blocks by adding extra chain weight (`vpcCertBoost = perasWeight params`). A certificate accepted into the `PerasCertDB` causes the chain selection logic to prefer the boosted block's chain over competing chains of equal or slightly greater length. Because the degenerate instance accepts every certificate regardless of its cryptographic content, an unprivileged peer can:

1. Forge a `PerasCert` with an arbitrary `pcBoostedBlock` pointing to any block on any fork.
2. Transmit it via the Peras object-diffusion mini-protocol.
3. The receiving node inserts it into `PerasCertDB` without signature verification.
4. Chain selection applies the boost weight, causing the node to prefer the attacker-chosen fork.

This matches the allowed impact scope: **Critical — bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance**, and **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The degenerate instance is in production source code (not in a test or benchmark library) and is the only `BlockSupportsPeras` instance visible for the general `blk` type variable. The explicit `TODO` comments referencing GitHub issue `#120` confirm this is a known placeholder that has not been replaced with real validation. Any node running with Peras activated and using the default instance is immediately vulnerable to a peer sending a single crafted certificate. No privileged access, key material, or stake majority is required.

---

### Recommendation

Before activating Peras on any network, replace the stub `validatePerasCert` and `validatePerasVote` implementations with calls to the existing `implVerifyCert` / `implVerifyVote` logic in `Ouroboros.Consensus.Committee.WFALS` (or the `EveryoneVotes` equivalent), wired through the `PerasCertCompatibleWithVotingCommittee` / `PerasVoteCompatibleWithVotingCommittee` conversion layer already present in `Ouroboros.Consensus.Peras.Voting.Committee`. The `processCerts` call-site should receive a `validateCert` closure that invokes the real committee verification, not the degenerate instance. [5](#0-4) 

---

### Proof of Concept

On a private testnet with Peras activated:

1. Observe the `pcRoundNo` and `pcBoostedBlock` of a legitimate certificate to learn the current round.
2. Construct a `PerasCert` with `pcBoostedBlock` pointing to a minority-fork block and `pcSignature` set to any byte string (e.g., all zeros).
3. Send the certificate to a target node via the Peras object-diffusion mini-protocol.
4. `processCerts` calls `validateCert` (the degenerate instance), which returns `Right ValidatedPerasCert{..}` unconditionally.
5. The certificate is stored in `PerasCertDB` with `vpcCertBoost = perasWeight params`.
6. Chain selection now weights the minority-fork block with the full Peras boost, causing the node to switch to the attacker-chosen chain. [6](#0-5) [7](#0-6)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Committee.hs (L47-65)
```haskell
-- | Conversion between (concrete) Peras votes and (abstract) committee votes.
--
-- NOTE: the functional dependency @vote -> crypto@ explicitly ties each
-- concrete Peras vote type to a specific crypto scheme.
class
  PerasVoteCompatibleWithVotingCommittee vote crypto committee
    | vote -> crypto
  where
  toPerasVote ::
    Committee.Vote crypto committee ->
    Either PerasConversionError vote
  fromPerasVote ::
    vote ->
    Either PerasConversionError (Committee.Vote crypto committee)

-- | Conversion between (concrete) Peras certificates and (abstract) committee
-- certificates.
--
-- NOTE: the functional dependency @cert -> crypto@ explicitly ties each
```
