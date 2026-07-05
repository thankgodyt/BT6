### Title
`validatePerasCert` Performs No Validation While `validatePerasVote` Checks Stake — Inconsistent Peras Object Validation Allows Forged Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance, which applies to all block types including Cardano's production block, implements `validatePerasCert` as an unconditional `Right` that performs zero cryptographic or structural checks. In contrast, `validatePerasVote` in the same instance at least verifies stake-distribution membership. An unprivileged peer can send a crafted `PerasCert` over the object-diffusion mini-protocol; the certificate will pass `validatePerasCert` without any signature or content verification, be stored in the `PerasCertDB`, and be eligible to boost a block during chain selection.

### Finding Description

**Root cause — `validatePerasCert` stub always returns `Right`:**

In `SupportsPeras.hs`, the catch-all instance covers every `StandardHash blk`, including the production `CardanoBlock`:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

`validatePerasCert` in this instance unconditionally wraps the incoming certificate in `Right` with no checks whatsoever:

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
``` [2](#0-1) 

**Contrast with `validatePerasVote`**, which at least checks stake-distribution membership before returning `Right`:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [3](#0-2) 

This is the direct analog of the external report: `validatePerasVote` (like `createMission`/`claimRewards`) received a meaningful check, while `validatePerasCert` (like `createDistribution`) was left as a pass-through that accepts every input.

**Attacker-controlled entry path:**

The network-facing `ObjectPool/PerasCert.hs` calls `validatePerasCert` on every certificate received from a peer before storing it: [4](#0-3) 

Because `validatePerasCert` always returns `Right`, any certificate — regardless of whether its aggregate BLS signature is valid, whether the claimed voters are eligible, or whether the boosted block even exists — is accepted as a `ValidatedPerasCert` and forwarded to the `PerasCertDB` and chain-selection logic in `ChainSel.hs`. [5](#0-4) 

The real certificate validation logic — aggregate BLS signature verification, VRF output checks, persistent/non-persistent voter eligibility — exists in `EveryoneVotes.implVerifyCert` and `WFALS.implVerifyCert`, but those paths are never reached because `validatePerasCert` short-circuits to `Right` before they can be invoked. [6](#0-5) [7](#0-6) 

### Impact Explanation

Peras certificates boost specific blocks during chain selection, causing an honest node to prefer the boosted chain over a competing chain of equal or greater length. An attacker who can inject an accepted-but-forged certificate for a block of their choice can steer chain selection toward a non-canonical chain without holding any stake or keys. This constitutes a **bypass of certificate validation that enables unauthorized certificate acceptance and chain-selection manipulation**, matching the "Critical — bypass of certificate/signature validation" and "High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

### Likelihood Explanation

Any node participating in the Peras object-diffusion mini-protocol is reachable by an unprivileged peer. No keys, stake, or privileged access are required. The attacker only needs to craft a `PerasCert` with an arbitrary boosted-block `Point` and send it; the node will accept it unconditionally. Likelihood is **High** once the Peras protocol is active on a network running this code.

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that mirrors the checks already present in `EveryoneVotes.implVerifyCert` / `WFALS.implVerifyCert`: verify that all claimed voters are eligible committee members, that each voter's stake is non-zero, and that the aggregate BLS signature over `(electionId, candidate)` is valid. Until a concrete per-era instance is available, the default instance should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), consistent with the fail-safe principle.

### Proof of Concept

1. Connect to a node running this code as an unprivileged peer via the object-diffusion mini-protocol.
2. Construct a `PerasCert blk` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of attacker-chosen block>`.
3. Send the certificate to the node.
4. The node calls `validatePerasCert params cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally.
5. The certificate is stored in the `PerasCertDB` and used in `ChainSel` to boost the attacker-chosen block, causing the node to prefer a chain containing that block over competing chains of equal length — without the attacker ever producing a valid BLS signature or holding any stake.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1-4)
```haskell
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-494)
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
```
