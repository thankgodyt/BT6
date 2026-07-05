### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Causes Incorrect Peras Voting Seat Counts for Voters with `lambda > ln(3)` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

### Summary

The `localSortitionNumSeats` function determines how many non-persistent Peras voting seats a committee member is entitled to, using a Taylor-expansion comparison (`taylorExpCmpFirstNonLower`) with a hardcoded error-bound parameter `boundX = 3`. The documented precondition for this parameter is `boundX = e^{|x|}`, but `x = -lambda` and `e^{lambda} > 3` whenever `lambda > ln(3) ≈ 1.099`. For any non-persistent voter whose expected seat count `lambda` exceeds this threshold — achievable with as little as ~1.1% of the non-persistent stake pool in a 100-seat committee — the error bound is underestimated, biasing the comparison toward granting more seats than the voter is entitled to. Because both the voter's self-check (`implCheckShouldVote`) and the verifier's check (`implVerifyVote`) call the same function, the inflated seat count is accepted by all nodes without disagreement.

### Finding Description

**Root cause — hardcoded `boundX` in `taylorExpCmpFirstNonLower`:**

In `localSortitionNumSeats`, the number of non-persistent seats is determined by:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- boundX (hardcoded)
      orders
      (-lambda)
``` [1](#0-0) 

The function comment at line 121 states the invariant explicitly:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Here `x = -lambda`, so the correct value is `boundX = e^{lambda}`. The hardcoded `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`.

**How `lambda` is computed:**

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
```
<cite repo="Noahgrantyt/ouroboros-consensus--014" path="ouroboros-consensus/src/ouroboros-consensus/Ou

### Citations

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
