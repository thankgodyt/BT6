### Title
Peras Certificate and Vote Validation Unconditionally Accepts Any Input Without Cryptographic Checks — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The sole production `BlockSupportsPeras` instance — a universal instance covering every `StandardHash blk` type including `CardanoBlock` — unconditionally returns `Right` (success) from `validatePerasCert` without performing any validation whatsoever, and accepts votes via `validatePerasVote` without verifying any cryptographic signature or VRF proof. This is the direct analog of the external report's pattern: a function that is supposed to perform a critical state-guarding check instead silently skips it, allowing any crafted input to pass as valid. On any network where Peras diffusion is active (including a private testnet), an unprivileged peer can forge certificates for arbitrary blocks and forge votes attributed to any registered stake pool without possessing the corresponding private keys.

### Finding Description

The degenerate `BlockSupportsPeras` instance is declared at line 320 of `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

Because this is an overlapping universal instance, it is the only `BlockSupportsPeras` instance that exists for all concrete block types. Its `validatePerasCert` implementation is:

```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [2](#0-1) 

No field of `cert` is inspected. No aggregate signature is verified. No round number, boosted block point, or quorum threshold is checked. Any `PerasCert blk` value, however crafted, is wrapped in `ValidatedPerasCert` and returned as `Right`. The `vpcCertBoost` field is set to `perasWeight params`, meaning the forged certificate carries the full configured weight boost.

The `validatePerasVote` implementation performs only a stake-distribution membership lookup:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [3](#0-2) 

The vote's cryptographic signature is never verified. The VRF eligibility proof is never checked. Any peer that knows a registered pool's `PoolId` (public information from the ledger) can craft a `PerasVote` attributed to that pool and have it accepted as `ValidatedPerasVote` with the pool's full ledger stake.

The `forgePerasCert` implementation similarly performs no quorum check — it accepts any `UniqueVotesWithSameTarget` and produces a `ValidatedPerasCert` unconditionally:

```haskell
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert = PerasCert { pcCertRound = ..., pcCertBoostedBlock = ... }
        , vpcCertBoost = perasWeight params
        }
``` [4](#0-3) 

The root cause is structurally identical to the external report: the function that is supposed to gate a critical state change (certificate/vote acceptance) instead always passes, because the condition that should reject invalid inputs is never evaluated. In the external report the condition `if (tx.amount > 0)` is never true because zero was passed; here the condition "if the aggregate signature is valid" is never evaluated because the check is absent entirely.

The `BlockSupportsPeras` class contract, as expressed by the `validatePerasCert` and `validatePerasVote` method signatures, requires that `Left` be returned on invalid input:

```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
``` [5](#0-4) 

The degenerate instance violates this contract for `validatePerasCert` (always `Right`) and partially violates it for `validatePerasVote` (never checks the signature).

### Impact Explanation

**Severity: Critical** — Bypass of Peras voting and certificate checks.

On any network where Peras vote/certificate diffusion is active:

1. **Forged votes**: An unprivileged peer that knows any registered pool's public identity (available from the ledger) can craft `PerasVote` messages attributed to that pool. `validatePerasVote` will accept them with the pool's full stake weight, because no signature is checked. The attacker does not need the pool's private key.

2. **Forged certificates**: An unprivileged peer can craft a `PerasCert` for any block at any round. `validatePerasCert` will accept it unconditionally and assign it the full `perasWeight` boost. No aggregate signature, no quorum threshold, no round validity is checked.

3. **Chain selection manipulation**: Accepted certificates carry a `vpcCertBoost` that feeds directly into `WeightedSelectView` and `wsvWeightBoost`, which drives `preferAnchoredCandidate`. A peer can therefore make an arbitrary block appear heavier than the honest chain tip, causing honest nodes to prefer a non-canonical chain. [6](#0-5) 

This satisfies the allowed impact scope: "Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance."

### Likelihood Explanation

The entry path is an unprivileged peer sending crafted Peras protocol messages over the object diffusion mini-protocol. No keys, no stake, no operator access is required — only knowledge of a registered pool's public identity, which is on-chain public data. The vulnerability is reachable on any private testnet or staging network where Peras diffusion is enabled. The degenerate instance is the only instance in the codebase for all `StandardHash blk` types; there is no override for `CardanoBlock`.

### Recommendation

Before enabling Peras vote or certificate diffusion on any network:

1. **`validatePerasCert`**: Implement full aggregate-signature verification against the set of voters listed in the certificate, verify the round number is within the valid range, and verify the boosted block point is a known block. Return `Left` on any failure.

2. **`validatePerasVote`**: Add cryptographic signature verification of the vote body against the voter's registered verification key. Add VRF eligibility proof verification where required by the committee model. Return `Left InvalidVoteSignature` on failure.

3. **`forgePerasCert`**: Verify that the supplied votes actually reach quorum before producing a certificate.

4. Remove the universal degenerate instance and replace it with a proper per-era instance once the HFC plumbing referenced in issue #73 is complete, so that the type system prevents accidentally shipping stub implementations.

### Proof of Concept

On a private testnet with Peras diffusion active:

1. Read the ledger stake distribution to obtain any registered pool's `PoolId` (e.g., pool `P` with stake `s`).
2. Construct a `PerasVote` with `pvVoteRound = r`, `pvVoteBlock = someBlock`, `pvVoteVoterId = P`. The signature field can be any value (it is never checked).
3. Diffuse the vote to a target node. `validatePerasVote` looks up `P` in the stake distribution, finds stake `s`, and returns `Right (ValidatedPerasVote { vpvVote = vote, vpvVoteStake = s })`. The vote is accepted with full stake weight.
4. Repeat for enough fake votes to exceed the quorum threshold (all attributed to real pools, all with arbitrary signatures).
5. Call `forgePerasCert` with the accumulated fake votes. It returns `Right (ValidatedPerasCert { ..., vpcCertBoost = perasWeight params })` unconditionally.
6. Diffuse the forged certificate. `validatePerasCert` returns `Right` unconditionally. The certificate's weight boost is applied to `someBlock` in chain selection, causing honest nodes to prefer it over the canonical chain tip. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-303)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
