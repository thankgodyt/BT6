### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Inject Arbitrary Chain-Selection Weight Boosts - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate as valid without performing any cryptographic or semantic checks. Because this stub is wired into the production inbound-certificate processing path, an unprivileged peer can send a crafted `PerasCert` that boosts any block by `perasWeight` (15 chain-selection weight units), causing an honest node to prefer a non-canonical chain when Peras is enabled.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must be passed before a certificate received from a peer is admitted into the `PerasCertDB` / `ChainDB` and used to boost a block's chain-selection weight.

The default instance (applied to every `StandardHash blk`) is a stub that always returns `Right`:

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

No check is performed on:
- the aggregate BLS signature over the election ID and boosted block hash,
- whether the declared voters are legitimate committee members,
- whether the quorum stake threshold is met, or
- any other validity criterion defined in CIP-0140.

This stub is directly called in the **production** inbound-certificate processing path. `makePerasCertPoolWriterFromChainDB` constructs the writer that handles certificates arriving from peers, and it passes `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then calls this function for every certificate not already in the DB, and on `Right` immediately timestamps and adds the certificate via `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [3](#0-2) 

Once admitted, the certificate is stored in the `PerasCertDB` and its boost is reflected in the `PerasWeightSnapshot` used by chain selection:

```haskell
, getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
-- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
-- all blocks newer than the current immutable tip.
``` [4](#0-3) 

The `BlockSupportsPeras` class also exposes a real BLS-based verification path (`implVerifyCert` in `EveryoneVotes` and `WFALS` committee implementations), confirming that the stub is a placeholder, not an intentional design: [5](#0-4) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the VolatileDB.
2. Send it via the ObjectDiffusion mini-protocol.
3. The node accepts it unconditionally (stub always returns `Right`).
4. The targeted block receives a `PerasWeight 15` boost in chain selection.
5. A fork containing that block now has 15 additional weight units, potentially making it heavier than the honest chain.
6. The node switches to the adversarially boosted, non-canonical chain.

This is a **bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and chain-selection manipulation**, matching the "High" impact tier: *"Bypass of leader eligibility, VRF/KES/certificate/signature validation, PBFT/Praos/TPraos/Peras voting or certificate checks... that enables unauthorized block, vote, or certificate acceptance"* and *"Chain selection... bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

- **Entry point is fully reachable** from any untrusted NTN peer via the ObjectDiffusion mini-protocol; no special privileges are required.
- **No cryptographic barrier** exists: the stub accepts any byte sequence that deserializes into a `PerasCert`.
- **Conditional on Peras being enabled**: the CHANGELOG notes Peras is disabled by default, but the code path is live and the vulnerability is present in any deployment that enables Peras.
- The `PerasCertDB` deduplicates by `PerasRoundNo`, so an attacker can inject one fraudulent certificate per round, which is sufficient to persistently bias chain selection for that round.

---

### Recommendation

Replace the stub `validatePerasCert` in the default `BlockSupportsPeras` instance with a real implementation that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the declared voters' aggregated public keys.
2. Checks that all declared voters are registered committee members with non-zero stake.
3. Verifies that the total stake of the voters meets the `perasQuorumStakeThreshold`.
4. For non-persistent voters, verifies their VRF eligibility proofs.

Until the real implementation is in place, the stub should be replaced with `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that no certificate from an untrusted peer can influence chain selection.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a Peras-enabled node as a normal NTN peer.
2. Attacker sends a `PerasCert` message via the ObjectDiffusion protocol with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <hash of a block on an adversarial fork>`
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams cert` returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}`.
4. The certificate is added to the `PerasCertDB` and the `PerasWeightSnapshot` is updated.
5. Chain selection now computes `totalWeightOfFragment` for the adversarial fork as `blockNo + 15`, potentially exceeding the honest chain's weight.
6. The node switches to the adversarial fork.

**Root cause line:**

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [6](#0-5)

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
