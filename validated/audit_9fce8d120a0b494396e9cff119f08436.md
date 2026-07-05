### Title
Degenerate `BlockSupportsPeras` Instance Unconditionally Accepts Any Peras Certificate Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance for `StandardHash blk` implements `validatePerasCert` as an unconditional `Right` — it accepts every certificate without performing any cryptographic or semantic check. The same instance implements `validatePerasVote` with only a stake-distribution lookup, skipping all signature verification. Both functions are called by the live ObjectDiffusion mini-protocol handlers (`ObjectPool/PerasCert.hs`, `ObjectPool/PerasVote.hs`), so any unprivileged peer can inject an arbitrary, structurally-valid Peras certificate or vote that the node will accept as `ValidatedPerasCert` / `ValidatedPerasVote` and propagate.

---

### Finding Description

**Root cause — missing verification step (the "missing approval" analog)**

In the original report, `UniV3PoolHelper` calls `UniV3TokenizedLp.deposit()`, which internally calls `transferFrom(helper, …)`. Because `helper` never called `approve()`, the pull fails. The structural analog here is:

| Smart-contract flow | Consensus flow |
|---|---|
| Caller must call `approve()` before callee can pull tokens | Caller must supply a real cryptographic check before `validatePerasCert` can produce a `ValidatedPerasCert` |
| `approve()` is never called → `transferFrom` reverts | Cryptographic check is never implemented → `validatePerasCert` always returns `Right` |

The degenerate instance is declared at:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

`validatePerasCert` returns `Right` for **every** input certificate, regardless of its round number, boosted-block hash, aggregate BLS signature, or any other field. No signature is verified, no round-number bounds are checked, no boosted-block existence is confirmed.

`validatePerasVote` is only marginally better — it checks that the voter's pool ID appears in the stake distribution, but performs **no signature verification**:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [2](#0-1) 

**Call sites in production mini-protocol handlers**

Both functions are invoked directly by the ObjectDiffusion object-pool handlers: [3](#0-2) [4](#0-3) 

These handlers sit on the network-facing ObjectDiffusion mini-protocol, reachable by any peer without privilege. A received `PerasCert` is passed to `validatePerasCert`; because the degenerate instance always returns `Right`, the result is a `ValidatedPerasCert` that the node stores and re-diffuses as if it were genuine.

**Contrast with the real implementations**

The `EveryoneVotes` and `WFALS` committee implementations contain full `implVerifyCert` functions that traverse every voter seat, reconstruct aggregate BLS verification keys, and call `verifyAggregateVoteSignature`: [5](#0-4) [6](#0-5) 

The degenerate instance performs none of these steps.

---

### Impact Explanation

**Severity: Critical**

The Peras protocol uses certificates to "boost" specific blocks, increasing their chain-selection weight by `perasWeight`. A `ValidatedPerasCert` produced by the degenerate instance carries a full `vpcCertBoost = perasWeight params` weight. Any peer can therefore:

1. Craft a `PerasCert` pointing to an arbitrary block (including an adversarially-chosen fork tip).
2. Send it over the ObjectDiffusion mini-protocol.
3. The receiving node calls `validatePerasCert`, which returns `Right` unconditionally.
4. The node stores the certificate and applies its boost to chain selection.
5. The node may switch to a non-canonical or adversarially-controlled chain that would otherwise lose the chain-selection comparison.

This is a **bypass of Peras certificate/vote verification that enables unauthorized certificate acceptance**, matching the allowed critical impact scope: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

**High.** The ObjectDiffusion mini-protocol is network-facing and requires no authentication. Any peer that can open a connection can send a crafted `PerasCert`. The degenerate instance is the only instance in scope for all block types until a proper Cardano-specific instance is wired in. The TODO comments reference open issues, confirming the bypass is present in the current codebase and not gated behind a feature flag.

---

### Recommendation

1. **Remove or restrict the degenerate instance.** Do not provide a catch-all `instance StandardHash blk => BlockSupportsPeras blk` that silently succeeds. Either make `validatePerasCert` and `validatePerasVote` return `Left` (reject everything) until a real implementation exists, or remove the instance entirely and require explicit opt-in.

2. **Implement full cryptographic verification** in `validatePerasCert` before the Peras certificate diffusion path is enabled in production. At minimum, verify the aggregate BLS signature against the reconstructed aggregate public key of the claimed voters, verify each voter's eligibility, and check round-number bounds.

3. **Gate the ObjectDiffusion handlers** behind a runtime feature flag that is disabled until the real `BlockSupportsPeras` instance is in place, so the network-facing entry point cannot be reached with the degenerate implementation active.

---

### Proof of Concept

1. Connect to a node running the degenerate `BlockSupportsPeras` instance via the ObjectDiffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = any round number
   - `pcCertBoostedBlock` = the tip of an adversarially-chosen fork
   - `pcSignature` = any byte string (e.g., all zeros)
3. Send the certificate over the wire.
4. The node calls `validatePerasCert params cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally.
5. The node stores the certificate and applies the Peras boost to the adversarially-chosen fork during chain selection.
6. If the boost is sufficient to tip the chain-selection comparison, the node switches to the adversary's fork, diverging from the honest chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L293-337)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-540)
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
```
