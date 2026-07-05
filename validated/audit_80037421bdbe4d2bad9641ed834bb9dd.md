### Title
`validatePerasCert` Implemented as Unconditional No-Op Stub Bypasses Peras Certificate Cryptographic Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` type class declares `validatePerasCert` as the security-critical method for validating Peras certificates received from peers over the object-diffusion mini-protocol. The only concrete instance — a degenerate instance covering all block types — implements this method as a stub that unconditionally returns `Right` (success), performing zero cryptographic or semantic checks. Because `processCerts` calls this function as its sole gate before adding a certificate to the `PerasCertDB`, any certificate sent by an unprivileged peer passes validation and is stored. The `PerasCertDB` is then consumed by chain selection to boost block weights, enabling a peer to manipulate chain selection with forged certificates.

---

### Finding Description

**Root cause — no-op stub in the only `BlockSupportsPeras` instance:**

In `BlockSupportsPeras.hs`, the type class declares:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The sole concrete instance (lines 320–358) implements it as:

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

This always returns `Right`, regardless of the certificate's aggregate BLS signature, round number, boosted-block identity, or any other field. [1](#0-0) 

**Attacker-controlled entry path — `processCerts`:**

`processCerts` in the Peras certificate object-pool handler receives raw `PerasCert` values from a remote peer and calls the injected `validateCert` (instantiated to `validatePerasCert`) on each one:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Because `validateCert` always returns `Right`, the `(errs, _)` branch is never taken. Every certificate from the peer is unconditionally promoted to `ValidatedPerasCert` and inserted into the `PerasCertDB`. [2](#0-1) 

**Downstream effect — chain selection:**

`chainSelSync` in `ChainSel.hs` processes `ChainSelAddPerasCert` events. It calls `PerasCertDB.addCert` with the already-"validated" certificate and then triggers `chainSelectionForBlock` for the boosted block, giving it extra Peras weight in the chain-order comparison. A certificate that was never cryptographically verified can therefore shift chain selection toward an attacker-controlled fork. [3](#0-2) 

**Structural parallel to the external report:**

The external report describes a contract that *inherits* a pause mechanism but never *overrides* the required methods, leaving the mechanism permanently inert. Here, `BlockSupportsPeras` *declares* `validatePerasCert` as the certificate-verification gate but the only *instance* is a stub that always succeeds — the declared security mechanism is present in the interface but permanently inert in the implementation. [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with a forged aggregate BLS signature, an arbitrary `pcCertRound`, and an arbitrary `pcCertBoostedBlock` pointing to any block in the VolatileDB. The certificate passes `validatePerasCert` unconditionally, is stored in the `PerasCertDB`, and its `vpcCertBoost` weight is applied during chain selection. This lets the peer make an honest node assign extra weight to a non-canonical fork, potentially causing it to switch away from the canonical chain — a chain-selection safety failure driven entirely by unauthenticated peer input.

Impact classification: **High** — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is compiled into the production codebase and the `processCerts` handler is wired up. Any peer that can establish a connection and send `PerasCert` objects over the mini-protocol can trigger this path. No keys, stake, or operator access are required. The Peras protocol is under active development (multiple `TODO` markers reference open issues), so the attack surface depends on whether the mini-protocol is enabled in deployed nodes; however, the vulnerable code is present and reachable in the current codebase.

---

### Recommendation

Replace the no-op stub with a real implementation of `validatePerasCert` that verifies the aggregate BLS signature against the claimed voters' public keys and the election identifier, consistent with the `implVerifyCert` logic already implemented in `Committee/WFALS.hs` and `Committee/EveryoneVotes.hs`. Until a real implementation is ready, the object-diffusion mini-protocol for Peras certificates should be disabled or the `processCerts` handler should reject all certificates rather than accepting them unconditionally. The same applies to `validatePerasVote`, which also omits signature verification. [5](#0-4) 

---

### Proof of Concept

1. Connect to a target node that has the Peras object-diffusion mini-protocol enabled.
2. Construct a `PerasCert` with:
   - `pcCertRound` set to a recent round number not yet in the node's `PerasCertDB`.
   - `pcCertBoostedBlock` pointing to the tip of an attacker-controlled fork present in the node's VolatileDB.
   - Any (invalid) aggregate BLS signature field — the value is irrelevant because `validatePerasCert` ignores it.
3. Send the certificate via the mini-protocol. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
4. The certificate is inserted into the `PerasCertDB`. `chainSelSync` fires `chainSelectionForBlock` for the boosted block, adding `vpcCertBoost` weight to the attacker's fork.
5. If the boosted weight tips the `ChainOrder` comparison, the node switches to the attacker's fork — a chain-selection outcome driven by a certificate whose signature was never verified. [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L278-320)
```haskell
class
  ( Show (PerasCfg blk)
  , NoThunks (PerasCert blk)
  ) =>
  BlockSupportsPeras blk
  where
  type PerasCfg blk

  data PerasCert blk

  data PerasVote blk

  data PerasValidationErr blk

  data PerasForgeErr blk

  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)

  forgePerasCert ::
    PerasCfg blk ->
    ValidatedPerasVotesWithQuorum blk ->
    Either (PerasForgeErr blk) (ValidatedPerasCert blk)

  -- | Extract a Peras certificate optionally stored in a block.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  getPerasCertInBlock ::
    blk ->
    Maybe (PerasCert blk)

-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-586)
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
