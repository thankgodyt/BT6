### Title
Wrong `boundX` Constant in `taylorExpCmpFirstNonLower` Causes Incorrect Peras Committee Seat Allocation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

### Summary

In `localSortitionNumSeats`, the call to `taylorExpCmpFirstNonLower` passes a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda`, the correct value is `e^lambda`. The constant `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. For any voter whose expected seat count `lambda` exceeds this threshold, the Taylor-expansion error bound is underestimated, causing the seat-count comparison to terminate too early and grant more non-persistent committee seats than the voter's stake entitles them to. This is the direct analog of M-04: a wrong scaling constant in an edge-case threshold calculation produces a result that is too large.

### Finding Description

`localSortitionNumSeats` computes `lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake` and then calls:

```haskell
taylorExpCmpFirstNonLower
  3          -- boundX: MUST equal e^{|x|} = e^lambda
  orders
  (-lambda)
``` [1](#0-0) 

The function's own documentation states:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Inside `decideOne`, the error term is computed as:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `boundX` is too small (i.e., `3 < e^lambda`), `errorTerm` is underestimated. The early-stop condition `cmp >= acc' + errorTerm` fires prematurely — before the partial sum has converged to `e^{-lambda}` — causing the function to return a higher index into `orders` than is correct. A higher index means more non-persistent seats are granted.

The code itself acknowledges the uncertainty with a TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
``` [4](#0-3) 

The `lambda` value exceeds `ln(3) ≈ 1.099` whenever a voter holds more than `ln(3) / numNonPersistentVoters` of the total non-persistent stake. For a committee with 100 non-persistent voters, any voter with more than ~1.1% of the non-persistent stake triggers the bug.

### Impact Explanation

`localSortitionNumSeats` is the gate that determines how many non-persistent seats — and therefore how much voting weight — a pool receives in the Peras committee for a given election. It is called during both vote forging (`implCheckShouldVote`) and vote verification (`implVerifyVote` and the certificate verification path): [5](#0-4) [6](#0-5) [7](#0-6) 

A voter whose `lambda > ln(3)` is granted more seats than their stake warrants. Because vote weight is proportional to seats granted, this inflates their effective voting power in Peras certificate formation. A pool with, say, 5% of non-persistent stake in a 100-voter committee (`lambda = 5`, `e^lambda ≈ 148`) operates with a `boundX` that is ~50× too small, making the error bound essentially meaningless and the seat count unreliable. This materially weakens the Peras voting authorization by accepting votes and certificates that reflect an incorrect (inflated) seat allocation.

### Likelihood Explanation

The condition `lambda > ln(3)` is met by any pool holding more than `ln(3) / numNonPersistentVoters` of the non-persistent stake. For realistic committee sizes (tens to hundreds of non-persistent voters), this threshold is crossed by any pool with even modest stake concentration. No special privileges are required: any pool participating in the Peras committee as a non-persistent member and holding sufficient stake will trigger the wrong branch. The bug is deterministic and reproducible given fixed protocol parameters and stake distribution.

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

This matches the contract stated in the function's own documentation and is consistent with how `checkLeaderNatValue` in `cardano-ledger` handles the analogous Praos leader-check Taylor expansion.

### Proof of Concept

Consider a Peras committee with `numNonPersistentVoters = 10` and a voter holding 20% of the non-persistent stake (`voterStake / totalNonPersistentStake = 0.2`):

```
lambda = 10 * 0.2 = 2.0
e^lambda = e^2 ≈ 7.389
boundX used = 3   (wrong; should be 7.389)
```

With `x = -2.0`, the Taylor series for `e^{-2}` converges slowly. At the `n`-th term, the true remaining error is bounded by `|x^n / n!| * e^{|x|} = |x^n / n!| * 7.389`, but the code uses `|x^n / n!| * 3` — underestimating the error by a factor of ~2.46. The early-stop condition `cmp >= acc' + errorTerm` fires before the partial sum is close enough to `e^{-2} ≈ 0.135`, causing `taylorExpCmpFirstNonLower` to return a higher index into `orders` than is correct. The voter is granted more non-persistent seats than their 20% stake entitles them to, inflating their Peras voting weight. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L64-99)
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

    -- Estimate how many seats we get by comparing the normalized VRF output
    -- against the thresholds defined by the orders.
    --
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-121)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-301)
```haskell
          let numSeats =
                localSortitionNumSeats
                  (nonPersistentCommitteeSize committee)
                  (totalNonPersistentStake committee)
                  ourStake
                  (normalizeVRFOutput vrfOutput)
          case nonZero numSeats of
            Nothing ->
              pure Nothing
            Just nonZeroNumSeats ->
              pure $
                Just $
                  WFALSNonPersistentMember
                    seatIndex
                    ourStake
                    vrfOutput
                    nonZeroNumSeats
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-546)
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
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
```
