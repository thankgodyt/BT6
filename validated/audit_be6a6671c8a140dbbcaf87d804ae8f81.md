### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production certificate-ingestion path calls `validatePerasCert` as its sole gate before storing a peer-supplied Peras certificate and triggering chain selection. The only live instance of `validatePerasCert` is a stub that unconditionally returns `Right` — it performs no cryptographic or committee-membership checks whatsoever. A full `verifyCert` implementation exists in the `CryptoSupportsVotingCommittee` class but is never invoked during inbound certificate processing. An unprivileged peer can therefore inject an arbitrary `PerasCert` that boosts any block in the VolatileDB, causing the honest node to re-run chain selection with fabricated Peras weight and potentially switch to a non-canonical chain.

---

### Finding Description

**Root cause — always-`Right` stub:**

The universal `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as:

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

This instance is explicitly marked as a "degenerate instance for all blks to get things to compile": [2](#0-1) 

**Production ingestion path uses this stub directly:**

Both production pool writers pass `validatePerasCert mkPerasParams` as the `validateCert` argument to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [3](#0-2) 

`processCerts` calls `validateCert` on each inbound certificate and, if all pass, stores them: [4](#0-3) 

Because `validatePerasCert` always returns `Right`, every certificate from every peer passes this gate.

**The real validation exists but is never called:**

`verifyCert` in both `WFALS` and `EveryoneVotes` implementations performs full cryptographic validation: committee-membership lookup, aggregate BLS signature verification, and (for non-persistent voters) batch VRF output verification: [5](#0-4) [6](#0-5) 

None of this is wired into the inbound certificate processing path.

**Chain selection is triggered on every accepted certificate:**

After a certificate is stored in the `PerasCertDB`, `chainSelSync` in `ChainSel.hs` immediately triggers chain selection for the boosted block: [7](#0-6) 

---

### Impact Explanation

**Impact: High** — Chain-selection manipulation via fabricated Peras certificate weight.

Peras certificates boost the chain-selection weight of the block they reference (`vpcCertBoost = perasWeight params`). Because any peer-supplied certificate is accepted without validation, an attacker can:

1. Craft a `PerasCert` pointing to any block hash present in the target node's VolatileDB.
2. Send it via the object-diffusion mini-protocol.
3. The certificate is stored and chain selection is re-run with the fabricated boost applied to the attacker-chosen block.
4. If the boosted block is on a fork, the honest node may switch away from the canonical chain to the attacker-preferred fork, violating chain-selection safety.

This matches the **High** impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

**Likelihood: High.**

- The entry point is the publicly reachable object-diffusion mini-protocol; any connected peer can send `PerasCert` messages.
- No authentication, stake ownership, or cryptographic proof is required — the attacker only needs to know a valid block hash in the target's VolatileDB (obtainable via ChainSync).
- The stub is the *only* instance; there is no override for any block type.
- The TODO comment and linked issue confirm this is a known gap, not an intentional design choice.

---

### Recommendation

Replace the stub `validatePerasCert` call in both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` with a call that invokes the actual `verifyCert` from `CryptoSupportsVotingCommittee`, using the current epoch's `VotingCommittee` context (via `InterEpochVotingCommittee`). The `processCerts` function already has the correct structure to reject invalid certificates; it only needs a non-trivial validator to be passed in. [8](#0-7) 

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node running the Peras-enabled consensus stack.
2. Connect a malicious peer via the object-diffusion mini-protocol.
3. Observe (via ChainSync) a block hash `H` on a minority fork in the target's VolatileDB.
4. Construct a `PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <point with hash H> }`.
5. Send the certificate to the target node through the object-diffusion protocol.
6. The target calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
7. The certificate is stored in `PerasCertDB`; `chainSelSync` fires chain selection for block `H`.
8. If the Peras boost is large enough to overcome the canonical chain's length advantage, the node switches to the minority fork — a chain-selection safety violation caused entirely by an unauthenticated peer message.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L292-340)
```haskell
-- | Verify a certificate attesting the winner of a given election
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L25-47)
```haskell
data InterEpochVotingCommittee crypto committee
  = InterEpochVotingCommittee
  { currEpochVotingCommittee :: !(VotingCommittee crypto committee)
  , prevEpochVotingCommittee :: !(StrictMaybe (VotingCommittee crypto committee))
  }

-- | Construct an inter-epoch committee selection for the first epoch
mkInterEpochVotingCommittee ::
  CryptoSupportsVotingCommittee crypto committee =>
  VotingCommitteeInput crypto committee ->
  Either
    (VotingCommitteeError crypto committee)
    (InterEpochVotingCommittee crypto committee)
mkInterEpochVotingCommittee votingCommitteeInput = do
  votingCommittee <-
    mkVotingCommittee votingCommitteeInput
  pure $
    InterEpochVotingCommittee
      { currEpochVotingCommittee =
          votingCommittee
      , prevEpochVotingCommittee =
          SNothing
      }
```
