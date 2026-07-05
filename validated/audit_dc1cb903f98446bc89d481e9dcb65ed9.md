### Title
Missing Peras Certificate Validation Implementation Always Accepts Invalid Certificates - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

---

### Summary

The degenerate catch-all `BlockSupportsPeras` instance, which applies to **all** production block types via `instance StandardHash blk => BlockSupportsPeras blk`, implements `validatePerasCert` as an unconditional `Right` — no cryptographic or structural checks are performed. This is the direct analog of the missing `quoteLayerZeroFee()`: a required validation function exists in the interface but its body is a stub that always succeeds. When Peras is enabled, any peer-supplied certificate is accepted without verification, enabling unauthorized certificate acceptance and chain-selection weight manipulation.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting a Peras certificate:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only deployed instance — a catch-all that covers every `StandardHash blk`, including all Cardano/Shelley/Conway production block types — implements this as:

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

The same pattern applies to `validatePerasVote`, which performs no cryptographic check and only looks up the voter in the stake distribution: [2](#0-1) 

The catch-all instance is declared as:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [3](#0-2) 

Additionally, `stakeAboveThreshold` — the quorum gate used in `votesReachQuorum` — carries an explicit disclaimer that the units of `PerasVoteStake` and the quorum threshold may not match, meaning the quorum check itself may be computed incorrectly: [4](#0-3) 

The `PerasParams` bundle, which supplies `perasWeight` (the chain-selection boost assigned to a certified block), is now populated with concrete values: [5](#0-4) 

---

### Impact Explanation

**Impact: High** — Bypass of Peras certificate/vote verification checks that enables unauthorized certificate acceptance.

When Peras is enabled (i.e., `eraPerasRoundLength = PerasEnabled someLength` in `EraParams`), the Peras diffusion layer receives certificates from peers and calls `validatePerasCert` before storing or acting on them. Because the implementation unconditionally returns `Right`, a crafted certificate from any unprivileged peer is accepted and assigned the full `perasWeight` boost (currently `PerasWeight 15`). A boosted block is preferred in chain selection over an unboosted chain of equal or greater length. An adversary can therefore steer an honest node's chain selection toward an adversarially chosen block without possessing any stake, keys, or certificates.

This matches the allowed scope: *"Critical. Bypass of… Peras voting or certificate checks… that enables unauthorized… certificate acceptance."*

---

### Likelihood Explanation

**Likelihood: Medium** — The degenerate instance is in production source code and applies to all block types. Exploitation requires Peras to be activated (a non-`NoPerasEnabled` `eraPerasRoundLength` in the era configuration). The changelog entry confirming that `PerasParams` fields previously held `error "yet undefined"` have now been replaced with concrete values indicates active progression toward deployment. [6](#0-5) 

---

### Recommendation

Replace the degenerate `BlockSupportsPeras` instance with per-block-type instances that perform real cryptographic and structural validation before Peras is activated on any network. At minimum, gate the catch-all instance behind a compile-time or runtime assertion that Peras is disabled, so that enabling Peras without a real implementation causes an immediate, visible failure rather than silent acceptance of all certificates.

---

### Proof of Concept

1. Connect a crafted peer to a node running with Peras enabled.
2. Diffuse a `PerasCert` for an adversarially chosen block `B` (any round number, any boosted-block point).
3. The node calls `validatePerasCert params cert` → returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }` unconditionally.
4. Block `B` is now weighted 15 units heavier than any competing unboosted chain tip.
5. Chain selection prefers `B`, causing the honest node to adopt the adversary's chain.

The entry path is the Peras certificate diffusion miniprotocol; no keys, stake, or operator access are required.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L136-163)
```haskell
-- NOTE: At the moment there is no consensus from researchers/engineers on how
-- we go from the absolute stake of a voter in the ledger to the relative stake
-- of their vote in the voting commitee (given that the quorum is expressed as
-- a relative value of the voting commitee total stake).
--
-- So, for now you can consider this 'Rational' as the best approximation we
-- have at the moment of the concrete type for a relative vote stake that can be
-- compared to the quorum threshold value (also currently a 'Rational').
newtype PerasVoteStake = PerasVoteStake
  { unPerasVoteStake :: Rational
  }
  deriving newtype (Eq, Ord, Num, Fractional, NoThunks, Serialise)
  deriving stock Generic
  deriving Show via Quiet PerasVoteStake
  deriving Semigroup via Sum Rational
  deriving Monoid via Sum Rational

-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** changelog.d/20260421_144234_thomas.bagrel_sensible_default_peras_params.md (L1-10)
```markdown
<!--
A new scriv changelog fragment.

Uncomment the section that is right (remove the HTML comment wrapper).
For top level release notes, leave all the headers commented out.
-->

### Patch

- Define sensible default values for the `PerasParams` that were previously left as `error "yet undefined"`, following the guidelines given in the [Peras CIP](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0140) and [Peras design document](https://tweag.github.io/cardano-peras/peras-design.pdf).
```
