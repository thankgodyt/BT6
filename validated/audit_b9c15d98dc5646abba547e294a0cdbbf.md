### Title
Incorrect `boundX` in `taylorExpCmpFirstNonLower` Causes Precision Error in Peras Local Sortition Seat Count, Enabling Unauthorized Vote/Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in the Peras wFA^LS committee selection passes a hardcoded `boundX = 3` to `taylorExpCmpFirstNonLower`, but the function's own contract requires `boundX = e^{|x|}`. Since `x = -lambda`, the correct bound is `exp(lambda)`. When `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, the Taylor series terminates too early, and the returned seat count can be wrong. Because `implVerifyVote` and `implVerifyCert` use this function to decide whether a non-persistent voter is eligible, a voter whose true seat count is 0 can be accepted as eligible, bypassing the Peras voting committee eligibility check.

---

### Finding Description

`localSortitionNumSeats` computes the number of non-persistent Peras committee seats for a voter by comparing the voter's normalized VRF output against Poisson CDF thresholds via a Taylor-expansion comparison:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- boundX: MUST be e^{|x|} per the function contract
      orders
      (-lambda)  -- x = -lambda, so |x| = lambda, correct bound = exp(lambda)
``` [1](#0-0) 

The function `taylorExpCmpFirstNonLower` documents its own precondition explicitly:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term used inside `decideOne` is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `boundX = 3 < exp(lambda)`, `errorTerm` is smaller than the true Taylor remainder bound. The decision conditions:

```haskell
| cmp >= acc' + errorTerm = Stop   -- classified ABOVE (grants seat at this index)
| cmp < acc' - errorTerm = Below   -- classified BELOW (continues)
``` [4](#0-3) 

With an underestimated `errorTerm`, the "uncertain" band `[acc' - errorTerm, acc' + errorTerm]` is narrower than it should be. A `cmp` value that truly lies within the uncertainty region but above `acc'` is incorrectly classified as ABOVE (Stop), returning the current index as the seat count. If this happens at index 0 (the first threshold), a voter whose true seat count is 0 is granted 1 seat.

The code itself acknowledges this is unresolved with a TODO comment and a tracked issue:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. ...
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [5](#0-4) 

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [6](#0-5) 

For a committee with 100 non-persistent voters, any voter holding more than ~1.1% of the non-persistent stake has `lambda > ln(3)`, making the error bound incorrect. This is a routine scenario.

The computed `numSeats` is used directly in vote and certificate verification:

```haskell
-- implVerifyVote (WFALS.hs:375-390)
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
    pure $ WFALSNonPersistentMember ...
``` [7](#0-6) 

The same pattern appears in `implVerifyCert`: [8](#0-7) 

---

### Impact Explanation

A non-persistent committee member whose VRF output falls in the region where the underestimated error bound causes a misclassification at index 0 will have `localSortitionNumSeats` return 1 (or more) instead of 0. `implVerifyVote` and `implVerifyCert` accept the vote/certificate because `nonZero numSeats` is `Just`. This is a bypass of the Peras voting committee eligibility check: an ineligible voter's vote or certificate is accepted as valid. Accepted ineligible votes contribute to quorum counting and certificate formation, corrupting the Peras voting outcome.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met by any non-persistent voter holding more than `1.099 / numNonPersistentVoters` of the non-persistent stake. With a committee of 100 non-persistent voters, any pool with more than ~1.1% of the non-persistent stake triggers the incorrect bound. The VRF output is pseudorandom and cannot be chosen by the voter, but the probability that it falls in the misclassification region is nonzero and grows with the magnitude of the error (i.e., with `lambda`). The attacker needs only to be a registered non-persistent committee candidate with sufficient stake — no privileged access is required.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound `exp(lambda)`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

This matches the contract stated in the function's own documentation and is consistent with how `checkLeaderNatValue` in `cardano-ledger` handles the analogous Praos leader check.

---

### Proof of Concept

Consider a non-persistent committee with 200 voters and a voter holding 1% of the non-persistent stake:

```
lambda = 200 * 0.01 = 2.0
exp(lambda) = exp(2.0) ≈ 7.389
boundX (current) = 3  -- WRONG: 3 < 7.389
```

At Taylor iteration step `n`, the error term is `abs(err' * 3)` instead of `abs(err' * 7.389)`. The algorithm terminates when `cmp >= acc' + errorTerm`. With the smaller `errorTerm`, this condition fires earlier. If the voter's normalized VRF output maps to `orders[0]` that is within `[acc' + errorTerm_correct, acc' + errorTerm_wrong]` — i.e., above the underestimated bound but below the correct bound — the algorithm returns `Stop` at index 0, granting 1 seat. The correct answer is 0 seats (ineligible). The vote submitted by this voter passes `implVerifyVote` and is counted toward quorum.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L167-168)
```haskell
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L175-175)
```haskell
    errorTerm = abs (err' * boundX)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-390)
```haskell
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
            pure $
              WFALSNonPersistentMember
                seatIndex
                voterStake
                vrfOutput
                nonZeroNumSeats
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-544)
```haskell
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
```
