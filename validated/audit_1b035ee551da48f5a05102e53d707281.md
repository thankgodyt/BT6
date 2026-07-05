### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Taylor Error Bounds for `lambda > ln(3)`, Causing Wrong Non-Persistent Seat Counts in Peras Committee Eligibility - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. The `x` argument is `-lambda`, so the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099` — a realistic condition for any non-trivial committee — the error term is underestimated, causing the Taylor comparison to terminate prematurely with a wrong seat count. This incorrect count is used directly in `implVerifyVote` and `implVerifyCert` to gate non-persistent Peras committee membership, meaning a voter can be accepted when they should be rejected, or rejected when they should be accepted.

---

### Finding Description

`localSortitionNumSeats` computes `lambda` as the expected number of seats for a voter under a Poisson model:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
```

It then calls:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- <-- hardcoded boundX
      orders
      (-lambda)
```

The contract of `taylorExpCmpFirstNonLower` is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
```

With `x = -lambda`, the required value is `boundX = e^lambda`. The hardcoded `3` satisfies this only when `lambda ≤ ln(3) ≈ 1.099`.

Inside `decideOne`, the error term is:

```haskell
errorTerm = abs (err' * boundX)
```

When `boundX = 3 < e^lambda`, `errorTerm` is smaller than the true Taylor remainder bound. The two early-exit conditions:

```haskell
| cmp >= acc' + errorTerm = Stop          -- declared ABOVE
| cmp < acc' - errorTerm  = Below ...     -- declared BELOW
```

fire before the partial sum has actually converged to within the true error of the target value `e^{-lambda}`. The function returns an index that may be off by one or more, producing an incorrect `expectedSeats`. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

`localSortitionNumSeats` is called in three places, all of which gate Peras voting eligibility:

1. **`implCheckShouldVote`** — determines whether the local node should cast a non-persistent vote.
2. **`implVerifyVote`** — verifies an incoming non-persistent vote from a peer; if `numSeats` is non-zero the vote is accepted.
3. **`implVerifyCert`** — verifies a Peras certificate; each non-persistent voter's seat count is re-checked. [4](#0-3) [5](#0-4) 

When `lambda > ln(3)` and the error bound is underestimated, `taylorExpCmpFirstNonLower` may return `Just 0` (seat index 0 is "not certainly below") when the true answer is `Nothing` (all thresholds are genuinely below the VRF output). This causes `nonZero numSeats` to return `Just nonZeroNumSeats` instead of `Nothing`, and the vote is accepted as eligible. Conversely, a voter who should receive seats may be denied them, weakening quorum formation.

The net effect is that the Peras voting committee eligibility check — a core authorization gate — produces incorrect results for any voter whose `lambda` exceeds `ln(3)`.

---

### Likelihood Explanation

`lambda = numNonPersistentVoters * (voterStake / totalNonPersistentStake)`. For `lambda > 1.099`, it suffices that a voter holds more than `1.099 / numNonPersistentVoters` of the non-persistent stake. With 10 non-persistent voters, any voter with more than ~11% of the non-persistent stake triggers the bug. With 20 non-persistent voters, the threshold drops to ~5.5%. These are entirely realistic stake distributions. No special privileges are required — any non-persistent committee candidate with sufficient stake will hit this condition on every election.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} where x = -lambda
      orders
      (-lambda)
```

This matches the contract stated in the function's own documentation and mirrors how `checkLeaderNatValue` in `cardano-ledger` handles the analogous leader eligibility check. The existing TODO at line 86–92 already flags uncertainty about this constant and should be resolved with this fix. [6](#0-5) 

---

### Proof of Concept

Consider a committee with:
- `numNonPersistentVoters = 10`
- `voterStake / totalNonPersistentStake = 0.20` (voter holds 20% of non-persistent stake)
- `lambda = 10 * 0.20 = 2.0`
- Correct `boundX = e^2.0 ≈ 7.389`; used `boundX = 3`

At the first Taylor step (`n=1`):
- `acc' = 1 + (-lambda) = 1 - 2 = -1`
- `err' = (-lambda)^2 / 2! = 4/2 = 2`
- Correct `errorTerm = 2 * 7.389 = 14.78`
- Actual `errorTerm = 2 * 3 = 6`

The actual error band `[-1 ± 14.78]` is much wider than the computed `[-1 ± 6]`. For a `cmp` value (from `orders`) in the range `[-7, 5]`, the code may declare ABOVE or BELOW when the true partial sum is still ambiguous, returning a seat count that differs from the correct Poisson-CDF result. A voter with `normalizedVRFOutput` placing `orders[0]` in this ambiguous zone will receive an incorrect seat count, causing `implVerifyVote` to accept or reject their vote incorrectly. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L64-81)
```haskell
    -- Expected number of seats granted by local sortition
    lambda :: FixedPoint
    lambda =
      fromRational $
        fromIntegral numNonPersistentVoters
          * voterStake
          / totalNonPersistentStake

    -- Compute the "orders" of the Poisson distribution with parameter lambda,
    -- which are used as thresholds to determine how many seats we get based on
    -- the normalized VRF output
    orders :: [FixedPoint]
    orders =
      (fromRational normalizedVRFOutput / lambda)
        : zipWith
          (\k prev -> k * prev / lambda)
          [2 ..]
          orders
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L86-99)
```haskell
    -- TODO(peras): evaluate whether the limit used below (3) makes sense in
    -- this context. One possible starting point would be to understand why
    -- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
    -- computing slot leadership proofs.
    --
    -- Tracked by this issue:
    -- https://github.com/tweag/cardano-peras/issues/234
    expectedSeats :: Int
    expectedSeats =
      fromMaybe 0 $
        taylorExpCmpFirstNonLower
          3
          orders
          (-lambda)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-125)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L165-175)
```haskell
  decideOne maxN n err acc divisor cmp
    | maxN == n = Stop
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
    | otherwise = decideOne maxN (n + 1) err' acc' divisor' cmp
   where
    divisor' = divisor + 1
    nextX = err
    acc' = acc + nextX
    err' = (err * x) / divisor'
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-543)
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
```
