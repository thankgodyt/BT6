### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Non-Persistent Seat Count When `lambda > ln(3)` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Taylor-series comparison helper `taylorExpCmpFirstNonLower` is called with a hardcoded error-bound parameter `boundX = 3`. The function's own inline contract states that `boundX` **must** equal `e^{|x|}` for the error bound to be valid. Because `x = -lambda` is passed, the required value is `e^lambda`. The constant `3` is only a valid upper bound when `lambda ≤ ln(3) ≈ 1.099`. For realistic Peras committee parameters, `lambda` routinely exceeds this threshold, causing the error term to be underestimated and the Taylor series to terminate with an incorrect seat count.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent Peras voting seats a pool is entitled to via a Poisson-distribution comparison over a Taylor expansion of `e^{-lambda}`:

```
lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [1](#0-0) 

The seat count is then determined by:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded boundX
      orders
      (-lambda)
``` [2](#0-1) 

The `taylorExpCmpFirstNonLower` function computes the error term as:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

The function's own contract is explicit:

> **IMPORTANT: boundX must be e^{|x|} for correct error bounds** [4](#0-3) 

Since `x = -lambda`, the required value is `e^lambda`. The hardcoded `3` satisfies this only when `lambda ≤ ln(3) ≈ 1.099`. When `lambda > 1.099`, `e^lambda > 3`, so `errorTerm` is underestimated, the uncertainty interval `[acc' - errorTerm, acc' + errorTerm]` is too narrow, and the algorithm may prematurely classify a comparison as `ABOVE` or `BELOW` when the true value is still uncertain — yielding a wrong seat count.

The developers themselves flagged this with a TODO:

> TODO(peras): evaluate whether the limit used below (3) makes sense in this context … Tracked by: https://github.com/tweag/cardano-peras/issues/234 [5](#0-4) 

The analogous `checkLeaderNatValue` in Praos uses the same constant `3`, but there `lambda = sigma * |ln(1-f)|` where `sigma` is a pool's stake fraction (≤1) and `f` is the active-slot coefficient (typically 0.05), giving `lambda ≤ 0.05`. For Praos, `3` is a safe overestimate. For local sortition, `lambda` is scaled by `numNonPersistentVoters`, making it orders of magnitude larger.

**Concrete threshold breach example**: With 10 non-persistent seats and a pool holding 15% of the non-persistent stake, `lambda = 10 × 0.15 = 1.5 > ln(3)`. With 50 non-persistent seats and a 5% stake fraction, `lambda = 2.5`. Both are realistic production scenarios.

---

### Impact Explanation

The incorrect seat count flows directly into vote verification in `implVerifyVote`:

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
    pure $ WFALSNonPersistentMember seatIndex voterStake vrfOutput nonZeroNumSeats
``` [6](#0-5) 

Two failure modes arise:

1. **Inflated seat count**: A pool near a Poisson threshold is granted more seats than the protocol intends. Because non-persistent vote weight is proportional to seat count, this inflates the pool's voting power, potentially allowing a minority of stake to reach quorum and forge a Peras certificate for a block that would otherwise fail the quorum check.

2. **Deflated seat count (denial)**: A legitimately eligible pool is computed to have zero seats and is rejected with `ZeroNonPersistentSeats`, silently excluding a valid voter from the committee. This weakens liveness and can skew quorum toward adversarial pools.

Both outcomes constitute a bypass of the Peras voting committee eligibility and seat-count rules.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is breached whenever:

```
numNonPersistentVoters × (voterStake / totalNonPersistentStake) > 1.099
```

With a target committee of 100 seats and a typical persistent/non-persistent split, a pool holding as little as ~1.1% of the non-persistent stake triggers the bug. This is well within the range of any mid-sized stake pool. No special privileges, leaked keys, or social engineering are required — only normal participation in the Peras protocol.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`, computed from the already-available `lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

This mirrors the contract stated in the function's own documentation and matches how `checkLeaderNatValue` in `cardano-ledger` is intended to be used (where `3` happens to be safe only because `lambda` is tiny for Praos slot leadership). Alternatively, if a conservative constant is preferred for performance, use `exp (fromIntegral numNonPersistentVoters)` as a worst-case upper bound.

---

### Proof of Concept

Consider `numNonPersistentVoters = 10`, `voterStake / totalNonPersistentStake = 0.2`:

- `lambda = 10 × 0.2 = 2.0`
- Correct `boundX = e^2.0 ≈ 7.389`
- Hardcoded `boundX = 3`
- Underestimation factor: `7.389 / 3 ≈ 2.46×`

At `n`-th Taylor term, `err' = (-lambda)^n / n!` and `errorTerm = |err'| × boundX`. With `boundX = 3` instead of `7.389`, the error interval is 2.46× too narrow. For a VRF output that lands within `[acc' - 7.389×|err'|, acc' + 7.389×|err'|]` but outside `[acc' - 3×|err'|, acc' + 3×|err'|]`, the algorithm terminates early with the wrong classification — granting the voter either one seat too many or one seat too few compared to the mathematically correct Poisson threshold comparison. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L48-99)
```haskell
localSortitionNumSeats
  (NonPersistentCommitteeSize numNonPersistentVoters)
  (TotalNonPersistentStake (Cumulative (LedgerStake totalNonPersistentStake)))
  (LedgerStake voterStake)
  (NormalizedVRFOutput normalizedVRFOutput)
    -- None of the non-persistent voters have any stake => nobody gets a seat.
    -- NOTE: this check avoids the expensive computation below and also prevents
    -- division by zero when computing @orders@.
    | voterStake <= 0 = LocalSortitionNumSeats 0
    -- If the voter has stake close to zero, the conversion from 'Rational' to
    -- 'FixedPoint' for 'lambda' might underflow to zero, which would cause the
    -- "orders" computation below to divide by zero.
    | lambda <= 0 = LocalSortitionNumSeats 0
    -- This voter might be entitled to some seats => run the local sortition.
    | otherwise = LocalSortitionNumSeats (fromIntegral expectedSeats)
   where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-122)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
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
