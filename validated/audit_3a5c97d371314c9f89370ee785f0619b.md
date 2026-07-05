### Title
Peras Certificate Verification Bypass Allows Any Peer to Inject Arbitrary Chain-Selection Weight Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `validatePerasCert` implementation in the universal `BlockSupportsPeras` instance unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. An unprivileged peer can send a crafted `PerasCert` naming any block as the boosted target; the certificate passes "validation", is stored in the `PerasCertDB`, and its weight boost is applied during chain selection, potentially causing the node to prefer a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

The `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as an unconditional `Right`:

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

No aggregate BLS signature is verified, no committee membership is checked, no round validity is enforced, and no boosted-block eligibility is confirmed. [1](#0-0) 

**Inbound path — peer-supplied certificates reach `validatePerasCert` directly:**

`makePerasCertPoolWriterFromChainDB` wires the object-diffusion writer so that every batch of peer-supplied `PerasCert` values is passed through `processCerts` with `validatePerasCert mkPerasParams` as the sole gate:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- always returns Right
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` treats a `Right` result as proof of validity and immediately forwards the certificate to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Downstream effect — chain selection is triggered with the injected boost:**

`chainSelSync` processes the certificate: it stores it in `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block, applying the attacker-chosen weight to chain selection:

```haskell
certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `PerasWeight` boost stored in `ValidatedPerasCert.vpcCertBoost` is set to `perasWeight params` regardless of the certificate's content, and this boost is subsequently used by `getPerasWeightSnapshot` / `constructPreferableCandidates` to make a candidate chain appear heavier than the honest chain.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with:
- `pcCertRound` set to any round number not yet seen (bypassing the duplicate-round guard),
- `pcCertBoostedBlock` pointing to any block in the node's VolatileDB.

The node will accept the certificate without any cryptographic check, store it, and apply a Peras weight boost to the named block during chain selection. If the boosted block is on a minority fork, the node may switch away from the honest canonical chain. Because the `PerasCertDB` persists the certificate and the weight snapshot is used in every subsequent chain-selection comparison, the effect is durable until the boosted block becomes immutable or is garbage-collected.

This constitutes a **High** impact chain-selection manipulation: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any connected peer without authentication. The attacker needs only to:
1. Connect as a normal peer.
2. Send a well-formed (but cryptographically unsigned/forged) `PerasCert` CBOR message naming a target block already in the victim's VolatileDB.

No stake, no keys, and no prior knowledge beyond the target block's hash (observable from the ChainSync protocol) are required. The `TODO` comments in the source confirm this is a known incomplete state, but the code is wired into the live diffusion path.

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate BLS signature against the committee's aggregate public key, confirm the round number is within the valid window, and check that the boosted block is eligible per Peras rules. The `PerasBLSCrypto` infrastructure and `implVerifyCert` in `WFALS.hs` / `EveryoneVotes.hs` already provide the cryptographic primitives needed. [5](#0-4) 

2. Until full validation is in place, **do not expose the certificate inbound path to untrusted peers** in any deployment that uses Peras weight boosts for chain selection.

3. Track the linked issue (`https://github.com/tweag/cardano-peras/issues/120`) to ensure the stub is replaced before any production activation of the Peras extension.

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer (no keys, no stake)
  │
  ▼  object-diffusion mini-protocol
makePerasCertPoolWriterFromChainDB
  │
  ▼  processCerts
validatePerasCert mkPerasParams (PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = forkTip })
  │  ← always returns Right, no signature checked
  ▼
ChainDB.addPerasCertAsync
  │
  ▼  chainSelSync / chainSelectionForBlock
  Node applies PerasWeight boost to forkTip
  → chain selection may prefer attacker's fork
```

**Concrete steps:**

1. Observe the victim node's VolatileDB tip hashes via ChainSync (no privilege needed).
2. Pick a block hash `H` on a minority fork.
3. Construct a CBOR-encoded `PerasCert { pcCertRound = N, pcCertBoostedBlock = H }` where `N` is a round not yet in the victim's `PerasCertDB`.
4. Send it via the Peras certificate object-diffusion sub-protocol.
5. `validatePerasCert` returns `Right` unconditionally.
6. `chainSelSync` stores the cert and re-runs chain selection for block `H` with the injected boost weight (`perasWeight params`).
7. If the boost is large enough relative to the honest chain's length advantage, the node switches to the minority fork.

The only check that could stop this is the `olderThanImmTip` guard (the boosted block must not be older than the immutable tip), which is a timing constraint, not a cryptographic one. [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L487-492)
```haskell
  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L494-532)
```haskell
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
