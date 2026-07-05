### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Violates Its Own Error-Bound Contract When `lambda > ln(3)`, Producing Wrong Peras Committee Seat Counts — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract states **"IMPORTANT: boundX must be e^{|x|} for correct error bounds"**, where `x = -lambda`. When `lambda > ln(3) ≈ 1.099`, the supplied `boundX` is smaller than `e^lambda`, the error term is underestimated, and the Taylor-series comparison terminates with a wrong conclusion — granting a Peras non-persistent committee voter more or fewer seats than their stake warrants.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent Peras committee seats a voter receives via local sortition (Poisson sampling). The key quantity is:

```
lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake
```

It then calls:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- <-- hardcoded boundX
      orders
      (-lambda)
``` [1](#0-0) 

The contract of `taylorExpCmpFirstNonLower` is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The `errorTerm` used to decide whether the Taylor partial sum has converged is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `boundX < e^lambda`, `errorTerm` is smaller than the true tail-error bound. The two early-exit conditions:

```haskell
| cmp >= acc' + errorTerm = Stop   -- declared ABOVE (grants seat)
| cmp < acc' - errorTerm  = Below  -- declared BELOW (denies seat)
``` [4](#0-3) 

…can fire before the series has actually converged, producing a wrong seat count. The code itself acknowledges the value `3` is unvalidated:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [5](#0-4) 

`lambda` is bounded by `numNonPersistentVoters`. For any committee with more than one non-persistent seat, a voter holding more than `ln(3)/numNonPersistentVoters` of the non-persistent stake has `lambda > ln(3)`, violating the precondition. For example, with `numNonPersistentVoters = 10` and a voter holding 20% of non-persistent stake, `lambda = 2 > ln(3) ≈ 1.099`, so `e^lambda ≈ 7.4` while `boundX = 3`. [6](#0-5) 

---

### Impact Explanation

The Peras protocol uses the non-persistent seat count to weight votes and determine certificate validity. An incorrect seat count — either inflated or deflated — directly distorts the voting power of a committee member:

- **Inflated seat count** (false ABOVE at line 167): a voter receives more seats than their stake warrants, giving them disproportionate voting power. A sufficiently large inflation allows a minority-stake adversary to unilaterally form a quorum and force certificate acceptance for a block that honest nodes would not certify.
- **Deflated seat count** (false BELOW at line 168): an honest voter's votes are silently discarded, potentially preventing quorum and stalling Peras finality.

Both outcomes break the Peras voting/certificate check invariants. This matches the allowed impact: **"Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance."**

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met by any pool whose share of non-persistent stake exceeds `ln(3) / numNonPersistentVoters`. For a committee with 10 non-persistent seats this threshold is ~11% of non-persistent stake — a realistic holding for a mid-sized stake pool on Cardano mainnet. No special privileges, key compromise, or majority stake are required; the adversary only needs to hold a normal pool with sufficient stake and submit a valid block header carrying a VRF certificate. The computation is triggered on every Peras committee evaluation for that voter.

---

### Recommendation

Replace the hardcoded `3` with the correct value `e^lambda`, computed from the actual `lambda` used in the call:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} where x = -lambda
      orders
      (-lambda)
```

Since `FixedPoint` supports `exp` (it is a `Floating` instance via `Cardano.Ledger.BaseTypes`), this is a one-line fix. Alternatively, pass `boundX` as a parameter to `localSortitionNumSeats` so callers can supply the correct value and the contract is enforced at the call site.

---

### Proof of Concept

**Setup:** `numNonPersistentVoters = 10`, voter holds 30% of non-persistent stake.

```
lambda = 10 * 0.3 / 1.0 = 3.0
e^lambda = e^3 ≈ 20.09
boundX (hardcoded) = 3
```

The error bound used is `errorTerm = |err' * 3|`, but the true tail bound requires `|err' * 20.09|`. The error is underestimated by a factor of ~6.7×.

At Taylor term `n`, `err' = (-lambda)^n / n!`. For `lambda = 3`, the terms are large and oscillating; the partial sum `acc'` oscillates around `e^{-3} ≈ 0.0498`. With `boundX = 3`, the algorithm may declare the comparison settled when the true uncertainty is still ±6.7× larger than `errorTerm`, causing it to return the wrong index from `orders` — i.e., the wrong number of seats.

A voter with `lambda = 3` should on average receive 3 seats. With the wrong `boundX`, the algorithm may return 2 or 4 (or another wrong value) for a specific VRF output that falls in the ambiguous region, granting or denying seats incorrectly. An adversary who can choose their VRF output (by grinding slot leadership) can arrange for their VRF output to land in this ambiguous region and exploit the wrong decision.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L64-70)
```haskell
    -- Expected number of seats granted by local sortition
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L167-168)
```haskell
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L175-175)
```haskell
    errorTerm = abs (err' * boundX)
```
