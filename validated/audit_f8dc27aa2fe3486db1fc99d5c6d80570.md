### Title
Peras Certificate Validation Bypass Allows Arbitrary Chain-Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or quorum verification. Any unprivileged peer can inject a crafted `PerasCert` for an arbitrary block, causing the receiving node to accept it as a `ValidatedPerasCert` with a full `perasWeight` chain-selection boost, potentially making the node prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate that must verify a Peras certificate before it is stored and used in chain selection. The sole production instance — a blanket `instance StandardHash blk => BlockSupportsPeras blk` — implements this gate as an unconditional stub:

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

This stub is not isolated to tests. It is the only instance of `BlockSupportsPeras` and is wired directly into both production inbound certificate processing paths:

1. `makePerasCertPoolWriterFromCertDB` passes `(validatePerasCert mkPerasParams)` as the validator.
2. `makePerasCertPoolWriterFromChainDB` does the same, and this path additionally triggers `addPerasCertAsync` which fires chain-selection side-effects. [2](#0-1) 

The `processCerts` function calls `validateCert` on every inbound certificate and, if it returns `Right`, timestamps and stores it: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, **every** inbound `PerasCert` — regardless of whether it carries a valid aggregate BLS signature, a legitimate quorum of committee votes, or a real round number — is accepted and stored as a `ValidatedPerasCert` with a full `vpcCertBoost = perasWeight params`.

The analog to the external report is exact: just as both operators and admins incremented the same approval counter without role separation, here both legitimate and illegitimate certificates pass the same (absent) validation gate, bypassing the committee-membership and quorum checks that are supposed to enforce who may produce a valid certificate.

The `WFALS` committee implementation correctly defines separate persistent and non-persistent member types with distinct cryptographic proofs (`WFALSPersistentVote` vs `WFALSNonPersistentVote`), and `implVerifyCert` properly enforces them: [4](#0-3) 

However, this verification is never reached for inbound network certificates because `validatePerasCert` short-circuits the entire check.

---

### Impact Explanation

A `ValidatedPerasCert` with a non-zero `vpcCertBoost` is used by the `PerasWeightSnapshot` to add weight to the boosted block during chain selection. An attacker who injects a certificate pointing to an arbitrary block causes the node to apply a `perasWeight` boost to that block, potentially making a minority or adversarial fork appear heavier than the honest chain. This is a chain-selection integrity failure: an unprivileged peer can make an honest node prefer a non-canonical chain without holding any stake, keys, or committee membership. [5](#0-4) 

---

### Likelihood Explanation

The attack requires only sending a well-formed `PerasCert` CBOR message over the Peras certificate mini-protocol. No cryptographic keys, stake, or committee membership are needed. The `PerasCert` structure contains only a `PerasRoundNo` and a `Point blk` (slot + hash), both of which are public information observable on-chain. Any peer connected to the node can execute this attack immediately. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real verification that:

1. Verifies the aggregate BLS vote signature against the claimed committee members' public keys.
2. Confirms that the set of signers constitutes a valid quorum (total stake above `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. Validates VRF proofs for any non-persistent committee members included in the certificate.
4. Checks that the certificate's round number and boosted block point are within acceptable bounds.

The `implVerifyCert` function in `WFALS.hs` already implements the correct cryptographic verification logic and should be plumbed through to the `BlockSupportsPeras` instance once the HFC integration (issue #73 / #120) is complete. Until then, the stub should at minimum reject certificates rather than unconditionally accept them. [7](#0-6) 

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of an adversarial fork block>`.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
4. The certificate is stored via `addPerasCertAsync`, triggering chain selection.
5. The adversarial fork block now carries a `perasWeight` boost in the node's chain-selection weight computation, causing the node to prefer it over the honest chain if the boost is sufficient. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-210)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-548)
```haskell
-- | Verify a certificate attesting the winner of a given election
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
```
