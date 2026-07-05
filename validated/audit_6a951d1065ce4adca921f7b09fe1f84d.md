### Title
Unconditional `validatePerasCert` Acceptance Enables Fake Certificate Injection and Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. This is the direct analog of the PIL missing binary constraint: a constraint that must be enforced (certificate validity) is entirely absent. Any unprivileged peer can inject a crafted Peras certificate boosting an arbitrary block, causing honest nodes to assign inflated chain weight to an attacker-chosen chain tip and diverge from the canonical chain.

---

### Finding Description

**Root cause — missing validation constraint:**

In the universal `instance StandardHash blk => BlockSupportsPeras blk`, the `validatePerasCert` method is implemented as:

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

This instance is declared as `instance StandardHash blk => BlockSupportsPeras blk`, making it the operative instance for all block types in the codebase unless a more specific overlapping instance is defined. [2](#0-1) 

No more specific instance overriding `validatePerasCert` with real cryptographic checks exists anywhere in the production source tree (confirmed by grep across all `.hs` files — only `SupportsPeras.hs`, `PerasCert.hs`, and `PerasVote.hs` reference `validatePerasCert`). [3](#0-2) 

The same pattern applies to `validatePerasVote`, which only checks stake-distribution membership but never verifies the vote's cryptographic signature:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [4](#0-3) 

**What should be validated but is not:**

A correct `validatePerasCert` must verify at minimum:
1. The aggregate BLS signature over `(roundNo, boostedBlock)` is valid for the claimed voter set.
2. Each claimed voter's seat index is within the committee bounds.
3. Non-persistent voters supply a valid VRF eligibility proof.
4. The total vote weight of the voter set meets the quorum threshold.

The concrete committee implementation in `WFALS.hs` (`implVerifyCert`) performs all of these checks: [5](#0-4) 

But `implVerifyCert` is never wired into `validatePerasCert` — the production call site uses the stub that always returns `Right`.

**Attacker-controlled entry path:**

The Peras object diffusion mini-protocol receives certificates from peers and calls `validatePerasCert` on each one before storing it in the certificate pool: [3](#0-2) 

A `PerasCert blk` carries only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk` — both are freely chosen by the sender: [6](#0-5) 

Because `validatePerasCert` always returns `Right`, the attacker's certificate is accepted, stored, and its `vpcCertBoost = perasWeight params` is applied to the boosted block in chain selection.

---

### Impact Explanation

**Severity: High — Chain selection manipulation by unprivileged peer.**

A Peras certificate boosts the chain weight of the block it certifies. An attacker who can inject a fake certificate for an arbitrary block causes honest nodes to assign that block a higher `SelectView` weight than it legitimately earned. This lets the attacker make honest nodes prefer a non-canonical or attacker-controlled chain tip over the true canonical chain, violating the chain selection safety property of Ouroboros Peras.

This matches the allowed impact: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**High.** The attack requires only a network connection to a target node. No stake, no keys, no privileged access. The attacker constructs a `PerasCert` CBOR payload with any desired `pcCertRound` and `pcCertBoostedBlock`, sends it via the object diffusion protocol, and the node accepts it unconditionally. The `PerasCert` serialisation format is public and straightforward: [7](#0-6) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set.
2. Checks each voter's seat index is within committee bounds and that persistent/non-persistent eligibility proofs are valid.
3. Confirms the total stake of the voter set meets the quorum threshold via `stakeAboveThreshold`.

The logic already exists in `implVerifyCert` in `WFALS.hs` and `implVerifyCert` in `EveryoneVotes.hs`. The fix is to wire the appropriate committee-specific verifier into the `validatePerasCert` method of the concrete `BlockSupportsPeras` instance for Cardano blocks, rather than relying on the universal stub. [8](#0-7) 

---

### Proof of Concept

1. Connect to a target node running Peras-enabled consensus as an unprivileged peer.
2. Construct a CBOR-encoded `PerasCert` with:
   - `pcCertRound = <any round number>`
   - `pcCertBoostedBlock = <point of any block on an attacker-controlled fork>`
3. Send the certificate via the Peras object diffusion mini-protocol.
4. The node calls `validatePerasCert params cert` which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
5. The certificate is stored in the certificate pool and the attacker-chosen block receives a chain weight boost equal to `perasWeight params`.
6. Chain selection now prefers the attacker's fork over the canonical chain whenever the boost tips the `SelectView` comparison.

No cryptographic material, stake, or operator access is required at any step.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-1)
```haskell
{-# LANGUAGE GADTs #-}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-493)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L494-586)
```haskell
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
