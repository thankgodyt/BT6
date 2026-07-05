### Title
Peras Certificate and Vote Validation Stubs Accept All Peer-Supplied Objects Without Cryptographic Verification, Enabling Unauthorized Chain-Selection Weight Injection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance — which applies to all block types including Cardano blocks — implements `validatePerasCert` as an unconditional `Right` (accept-all stub) and `validatePerasVote` without any cryptographic signature check. Any unprivileged peer connected via the Peras object-diffusion mini-protocol can inject forged certificates or votes for arbitrary rounds and blocks. Accepted certificates are immediately queued for chain selection and provide a configurable weight boost to the attacker-chosen block, allowing the attacker to make an honest node prefer a non-canonical adversarial chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass in `SupportsPeras.hs` defines the interface for validating Peras certificates and votes. The sole concrete instance — explicitly marked as a "degenerate instance for all blks to get things to compile" — provides stub implementations for both `validatePerasCert` and `validatePerasVote`:

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

`validatePerasCert` accepts every certificate unconditionally. The peer-supplied `pcCertRound` and `pcCertBoostedBlock` fields are used directly with no cryptographic binding to any committee member's identity.

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`validatePerasVote` only checks that the claimed `pvVoteVoterId` appears in the stake distribution. No BLS vote signature is verified. Because voter IDs are public (derived from the stake distribution), any peer can impersonate any registered voter for any round and block.

Both stubs are wired into the production inbound processing paths:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

The `processCerts` function passes every certificate that is not already in the DB straight through to `ChainDB.addPerasCertAsync`: [5](#0-4) 

`chainSelSync` then processes the certificate, looks up the boosted block in the VolatileDB, and triggers `chainSelectionForBlock` for it: [6](#0-5) 

The weight boost stored in `ValidatedPerasCert.vpcCertBoost` is used by `getWeightSnapshot` / `getPerasWeightSnapshot` to make the boosted block's chain heavier during chain selection: [7](#0-6) 

The contrast with the proper cryptographic infrastructure that exists but is bypassed is stark: `WFALS.hs` contains a complete `implVerifyCert` that verifies aggregate BLS signatures and batch-verifies VRF outputs: [8](#0-7) 

None of that verification is invoked through the default instance.

---

### Impact Explanation

An attacker who can connect to a node as a peer via the Peras object-diffusion mini-protocol can:

1. **Certificate forgery**: Send a `PerasCert` with `pcCertBoostedBlock` pointing to any block in the VolatileDB (e.g., the tip of an adversarial fork). The stub accepts it unconditionally and assigns it the full `perasWeight` boost. Chain selection is immediately re-run for the boosted block. If the adversarial fork's accumulated weight (block count + Peras boost) exceeds the honest chain's weight, the node switches to the adversarial fork.

2. **Vote forgery leading to certificate creation**: Send `PerasVote` objects claiming to be multiple high-stake registered voters (voter IDs are public). Once the accumulated forged stake crosses the quorum threshold, `implAddVote` in `PerasVoteDB` automatically forges a certificate and queues it for chain selection — with no cryptographic evidence that any real committee member voted.

Both paths allow an unprivileged peer to inject unauthorized Peras weight boosts, directly manipulating which chain the node selects. This is a bypass of Peras certificate and vote verification checks that enables unauthorized certificate acceptance and chain-selection weight injection.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is wired into the production `ChainDB` code path (not gated behind a test flag). The `makePerasCertPoolWriterFromChainDB` and `makePerasVotePoolWriterFromChainDB` functions are production code in `ouroboros-consensus/src/`. Any peer that can establish a connection and speak the object-diffusion protocol can trigger this path. No stake, no keys, and no prior knowledge beyond public voter IDs are required. The attack is deterministic and requires only a single network message per forged certificate.

The primary uncertainty is whether the Peras object-diffusion mini-protocol is currently enabled in deployed Cardano nodes; the many `TODO` comments suggest Peras is still under active development. If the protocol is not yet negotiated in production, the attack surface is limited to private testnets or future deployments. However, the vulnerable code is unconditionally compiled into the production binary.

---

### Recommendation

Replace the stub `validatePerasCert` and `validatePerasVote` implementations with calls to the proper cryptographic verification already implemented in `WFALS.hs` (`implVerifyCert`, `checkVoteSignature`, `batchVerifyVRFOutputs`). Until real validation is in place, the object-diffusion mini-protocol for Peras certificates and votes should be disabled at the network negotiation layer so that no peer-supplied certificate or vote can reach `processCerts` / `processVotes`. The `TODO` comments referencing `https://github.com/tweag/cardano-peras/issues/120` should be treated as a security-blocking issue, not a deferred enhancement.

---

### Proof of Concept

**Certificate injection (private testnet):**

1. Connect to a target node as a peer that speaks the Peras object-diffusion protocol.
2. Observe the VolatileDB to identify the tip hash of an adversarial fork (`H_adv`) and its slot.
3. Craft a `PerasCert` CBOR message:
   ```
   PerasCert { pcCertRound = <current_round>, pcCertBoostedBlock = BlockPoint <slot> <H_adv> }
   ```
4. Send it via the object-diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
6. `ChainDB.addPerasCertAsync` enqueues the certificate; `chainSelSync` triggers `chainSelectionForBlock` for `H_adv`.
7. The adversarial fork now carries the full Peras weight boost; if it exceeds the honest chain's weight, the node switches.

**Vote forgery leading to automatic certificate creation:**

1. Read the public stake distribution to obtain `N` registered voter IDs whose combined stake exceeds the quorum threshold.
2. For each voter ID, craft a `PerasVote` with `pvVoteVoterId = <voter_id>`, `pvVoteRound = <target_round>`, `pvVoteBlock = <H_adv>`.
3. Send all votes via the object-diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each; each passes because the voter ID is in the stake distribution — no signature is checked.
5. `implAddVote` accumulates stake; once quorum is reached, `updatePerasRoundVoteStates` returns `VoteGeneratedNewCert cert`.
6. The forged certificate is automatically queued via `addPerasCertAsync`, triggering chain selection for `H_adv`. [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
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
