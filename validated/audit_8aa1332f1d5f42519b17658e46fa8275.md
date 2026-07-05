### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or structural checks. Any unprivileged peer can send a crafted `PerasCert` for an arbitrary round and block point via the node-to-node ObjectDiffusion miniprotocol. The certificate will be accepted as a `ValidatedPerasCert` carrying the full `perasWeight` boost, directly manipulating chain selection on the receiving node.

---

### Finding Description

The `BlockSupportsPeras` instance for all block types contains a stub implementation of `validatePerasCert`:

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

This stub skips all of the following checks that a correct implementation must perform:
- Aggregate vote signature verification
- Quorum threshold check (that the certificate actually represents enough stake)
- Committee membership eligibility of the voters listed in the certificate
- VRF output validity for non-persistent committee members

The inbound certificate processing path in `processCerts` calls this stub directly:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) [3](#0-2) 

The `processCerts` function is the production inbound handler for certificates received from peers. It filters already-known certs, calls `validateCert` on the rest, and adds all that pass to the `ChainDB` or `PerasCertDB`:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never taken. Every certificate from every peer passes validation and is stored.

The `PerasVoteDB` implementation has a parallel acknowledged stub:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ...
``` [5](#0-4) 

---

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is applied during chain selection to boost the weight of the certified block. By injecting a forged certificate for a block of the attacker's choice, an unprivileged peer causes the victim node to assign an unearned weight boost to that block. This directly manipulates chain selection: the node may prefer a non-canonical or adversary-controlled chain over the honest chain, constituting a consensus safety failure.

This is a **Critical** bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation, matching the allowed impact scope: *"Bypass of … certificate … checks … that enables unauthorized … certificate acceptance"* and *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

The attack path is fully reachable with no special privileges:

1. Any node-to-node peer connects via the standard miniprotocol.
2. The peer sends a crafted `PerasCert{pcCertRound = r, pcCertBoostedBlock = adversarialPoint}` via the ObjectDiffusion protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which unconditionally returns `Right`.
4. The cert is timestamped and added to the `ChainDB` via `addPerasCertAsync`.
5. Chain selection applies `perasWeight` to `adversarialPoint`.

The stub is in the production code path (`makePerasCertPoolWriterFromChainDB`), not gated by any feature flag or test-only guard. Likelihood is **High** once Peras is active on a network using this code.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a complete validation that:
1. Verifies the aggregate vote signature against the listed voters' verification keys.
2. Checks that the listed voters are eligible committee members (persistent or non-persistent) according to the current epoch's stake distribution and committee selection.
3. Verifies VRF outputs for non-persistent voters.
4. Confirms that the total stake of the listed voters meets the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
5. Checks that the certified block's slot satisfies `perasBlockMinSlots`.

The `CryptoSupportsAggregateVoteSigning` and `CryptoSupportsBatchVRFVerification` interfaces already exist in `Ouroboros.Consensus.Committee.Crypto` and are used correctly in `implVerifyCert` for both `EveryoneVotes` and `WFALS` committee schemes. The production `validatePerasCert` should delegate to the appropriate `verifyCert` implementation once the HFC plumbing (tracked in issue #73) is in place. [6](#0-5) [7](#0-6) 

---

### Proof of Concept

On a private testnet running this code with Peras active, an attacker node can execute the following sequence:

1. Connect to a victim node via the node-to-node protocol.
2. Craft a `PerasCert` targeting an adversary-controlled block at any round number:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <adversarial block point> }
   ```
3. Transmit the cert via the ObjectDiffusion cert miniprotocol.
4. On the victim node, `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. The cert is added to the `ChainDB`. Chain selection now applies `perasWeight` to the adversarial block.
6. If `perasWeight` is large enough (it is configurable and can be set to exceed the honest chain's density advantage), the victim node switches to the adversary's chain.

No key material, stake majority, or operator access is required. The only prerequisite is a standard peer connection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-562)
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
