### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Boost Arbitrary Blocks in Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation in `BlockSupportsPeras.hs` unconditionally accepts every inbound `PerasCert` as valid, performing zero cryptographic or structural checks. Any unprivileged peer can send a crafted certificate boosting an arbitrary block, causing the receiving node to apply the full Peras chain-weight boost to a non-canonical or adversarially chosen block and switch away from the honest chain.

---

### Finding Description

**Root cause.** The `BlockSupportsPeras` typeclass method `validatePerasCert` is the sole gate between a raw peer-supplied `PerasCert` and a `ValidatedPerasCert` that carries chain-selection weight. Its current production implementation is:

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

It returns `Right` for every input without checking:
- aggregate BLS signature validity
- quorum stake threshold (≥ 3/4 + safety margin)
- certificate round number within `perasCertMaxRounds`
- whether the boosted block point exists on any known chain

**Entry path.** Inbound certificates arrive from peers via the Peras cert mini-protocol and are processed by `processCerts` in `PerasCert.hs`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [2](#0-1) 

The `validateCert` argument is wired to `validatePerasCert mkPerasParams` in both the `PerasCertDB`-backed and `ChainDB`-backed pool writers: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every cert passes, is timestamped, and is forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection with the cert's boost applied.

**Boost magnitude.** The default `perasWeight` is 15, meaning the boosted block is treated as 15 blocks heavier than it actually is: [4](#0-3) 

**Analog to the external report.** The external report's `mint` function checked that a Bitcoin transaction was mined and confirmed but never verified the destination address, allowing the owner to mint from any valid transaction. Here, `validatePerasCert` checks that a certificate has a round number not already in the DB (deduplication only) but never verifies the cryptographic proof of quorum, allowing any peer to "mint" a chain-weight boost for any block.

---

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

An adversary controlling a single peer connection can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block (e.g., the tip of an adversarial fork).
2. Send it over the Peras cert mini-protocol.
3. The receiving node accepts it as `ValidatedPerasCert` with `vpcCertBoost = 15`.
4. Chain selection now treats the adversarial fork as 15 blocks heavier than the honest chain.
5. The node switches to the adversarial fork, causing a rollback of up to `perasWeight` (15) blocks of honest history.

This directly matches the allowed impact: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

The `ValidatedPerasCert` wrapper is the type-level trust boundary; once a cert is wrapped in it, all downstream code (chain selection, weight snapshots, cert DB) treats it as cryptographically proven. The bypass is total: no signature, no quorum, no round-range check is ever performed.

---

### Likelihood Explanation

**High.** The attack requires only a peer connection — no stake, no keys, no prior knowledge beyond the block hash of the target block (which is public). The `processCerts` path is exercised for every inbound cert batch. The TODO comment and linked issue (`#120`) confirm the stub is intentional but the code is already wired into the production diffusion layer.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature over the `(electionId, candidate)` pair using the committee's aggregate verification key.
2. Checks that the total stake of the signers meets `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin` (mirroring the existing `stakeAboveThreshold` check used during local cert forging).
3. Validates that the certificate's round number is within `perasCertMaxRounds` of the current tip.
4. Verifies VRF outputs for non-persistent voters (as `WFALS.implVerifyCert` already does for locally forged certs).

The `verifyCert` implementations in `WFALS.hs` and `EveryoneVotes.hs` already contain the correct cryptographic logic and should be called from `validatePerasCert` once the committee-selection plumbing is in place. [5](#0-4) [6](#0-5) 

---

### Proof of Concept

```
Attacker (peer) ──► sends PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialPoint }
                                                │
                    processCerts (PerasCert.hs:168)
                                                │
                    validatePerasCert mkPerasParams cert
                    ──► always returns Right (ValidatedPerasCert { vpcCertBoost = 15 })
                                                │
                    addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
                                                │
                    ChainSel: adversarialFork weight += 15
                    ──► node switches to adversarial fork (rollback of honest chain)
```

No stake, no cryptographic material, and no prior chain knowledge beyond the target block's `Point` is required. A single crafted `PerasCert` message suffices. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L293-340)
```haskell
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
