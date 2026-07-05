### Title
Hardcoded Magic-Number `boundX = 3` in `localSortitionNumSeats` Produces Incorrect Taylor-Series Error Bound for Peras Non-Persistent Seat Allocation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` calls `taylorExpCmpFirstNonLower` with a hardcoded first argument of `3`. The function's own contract (documented inline) requires that argument to equal `e^{|x|}` for correct error bounds. The actual `|x|` is `lambda`, so the correct value is `e^lambda`. The constant `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. For any realistic committee configuration where `lambda > 1.099`, the error bound is underestimated, the Taylor-series convergence check makes incorrect decisions, and the resulting non-persistent seat count is wrong. Because the same buggy function is used in both the forging path (`implCheckShouldVote`) and the verification path (`implVerifyCert`), a voter can claim an inflated seat count that the verifier will accept.

---

### Finding Description

`localSortitionNumSeats` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs` computes how many non-persistent Peras voting-committee seats a voter is entitled to, using a Poisson-distribution approximation via a Taylor-series comparison:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded magic number
      orders
      (-lambda)
``` [1](#0-0) 

The helper `taylorExpCmpFirstNonLower` is documented with an explicit precondition:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term inside the helper is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

Here `x = -lambda`, so `|x| = lambda`, and the mathematically correct `boundX` is `e^lambda`. The hardcoded value `3` satisfies the precondition only when `e^lambda ≤ 3`, i.e., `lambda ≤ ln(3) ≈ 1.099`.

`lambda` is computed as:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [4](#0-3) 

For a committee with `numNonPersistentVoters = 10` and a voter holding 15 % of non-persistent stake, `lambda = 1.5 > ln(3)`. For a voter holding 20 %, `lambda = 2.0`; `e^2 ≈ 7.39`, so the hardcoded `3` underestimates the true error bound by more than 2×. The larger `lambda` grows (it is bounded only by `numNonPersistentVoters`), the more severely the error bound is wrong.

When `boundX` is too small, `errorTerm` is too small. The algorithm then prematurely classifies borderline comparisons as "ABOVE" (i.e., `cmp >= acc' + errorTerm` fires too early), returning a higher index into `orders` than is correct. This inflates `expectedSeats` by one or more.

The same function is called identically in both the vote-forging path and the certificate-verification path:

- `implCheckShouldVote` → `localSortitionNumSeats` → inflated `numSeats` → voter claims extra seats
- `implVerifyCert` → `localSortitionNumSeats` → same inflated count → verifier accepts the inflated claim [5](#0-4) [6](#0-5) [7](#0-6) 

The code itself acknowledges the magic number is unvalidated:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [8](#0-7) 

---

### Impact Explanation

A non-persistent Peras committee member whose `lambda > ln(3)` will have their seat count computed incorrectly. Because the verifier uses the same buggy function, the verifier accepts the inflated seat count. Each extra seat translates directly into extra `VoteWeight` in `implEligiblePartyVoteWeight`, which is summed when deciding whether a Peras certificate threshold is met. An adversary who observes that their `lambda` falls in the affected range can forge votes and certificates claiming more voting power than their stake entitles them to, and honest nodes will accept those certificates. This can cause honest nodes to boost (and prefer) a block that should not have received a certificate, constituting a Peras voting/certificate check bypass and a chain-selection error.

---

### Likelihood Explanation

`lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. With any realistic non-persistent committee size above ~5 and any voter holding more than ~22 % of non-persistent stake, `lambda > 1.099`. This is a common configuration. The adversary needs no special privileges: they only need to be a registered stake pool that is a non-persistent committee candidate, observe their own `lambda`, and submit a vote/certificate claiming the inflated seat count. No key compromise, no majority stake, and no social engineering is required.

---

### Recommendation

Replace the hardcoded `3` with the dynamically computed `e^lambda`:

```haskell
import Cardano.Ledger.BaseTypes (fpExp)  -- or equivalent

expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (fpExp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

This mirrors the fix recommended in the analogous Oracle report: replace the magic constant with the on-chain/dynamically computed value. Additionally, add an assertion or property test that `boundX >= exp(abs x)` at the call site, and resolve the open TODO tracked at https://github.com/tweag/cardano-peras/issues/234.

---

### Proof of Concept

**Setup**: Peras committee with `numNonPersistentVoters = 10`, voter stake = 20 % of total non-persistent stake.

**Computation**:
- `lambda = 10 * 0.20 = 2.0`
- Correct `boundX = e^2 ≈ 7.389`
- Hardcoded `boundX = 3`
- Ratio: `3 / 7.389 ≈ 0.406` — the error bound is less than half the correct value

**Effect**: For a VRF output `normalizedVRFOutput` near the boundary between 2 and 3 seats (i.e., near `e^{-2} * lambda^2 / 2! ≈ 0.2707`), the Taylor series with `boundX = 3` will prematurely declare the comparison "ABOVE" before enough terms have been accumulated to distinguish the true result. The function returns `expectedSeats = 3` instead of the correct `2`.

**Attack path**:
1. Adversary observes their `lambda = 2.0 > ln(3)`.
2. Adversary computes `localSortitionNumSeats` locally; it returns `3` (inflated).
3. Adversary forges a `WFALSNonPersistentVote` claiming `nonZeroNumSeats = 3`.
4. `implVerifyCert` calls `localSortitionNumSeats` with the same inputs and the same buggy `boundX = 3`, also computing `3`.
5. `nonZero numSeats` succeeds; the certificate is accepted with the adversary contributing 3 seats' worth of `VoteWeight` instead of 2.
6. If the certificate threshold is met only because of this extra seat, honest nodes accept a certificate — and boost a block — that should not have been certified.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L65-70)
```haskell
    lambda :: FixedPoint
    lambda =
      fromRational $
        fromIntegral numNonPersistentVoters
          * voterStake
          / totalNonPersistentStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L86-92)
```haskell
    -- TODO(peras): evaluate whether the limit used below (3) makes sense in
    -- this context. One possible starting point would be to understand why
    -- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
    -- computing slot leadership proofs.
    --
    -- Tracked by this issue:
    -- https://github.com/tweag/cardano-peras/issues/234
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L93-99)
```haskell
    expectedSeats :: Int
    expectedSeats =
      fromMaybe 0 $
        taylorExpCmpFirstNonLower
          3
          orders
          (-lambda)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-121)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L175-175)
```haskell
    errorTerm = abs (err' * boundX)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-291)
```haskell
          let numSeats =
                localSortitionNumSeats
                  (nonPersistentCommitteeSize committee)
                  (totalNonPersistentStake committee)
                  ourStake
                  (normalizeVRFOutput vrfOutput)
          case nonZero numSeats of
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-381)
```haskell
        let numSeats =
              localSortitionNumSeats
                (nonPersistentCommitteeSize committee)
                (totalNonPersistentStake committee)
                voterStake
                (normalizeVRFOutput vrfOutput)
        case nonZero numSeats of
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-534)
```haskell
              let numSeats =
                    localSortitionNumSeats
                      (nonPersistentCommitteeSize committee)
                      (totalNonPersistentStake committee)
                      voterStake
                      (normalizeVRFOutput vrfOutput)
              case nonZero numSeats of
```
