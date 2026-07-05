### Title
Incorrect `boundX` Constant in Peras Local Sortition Taylor-Series Comparison Grants Excess Committee Seats — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` determines how many non-persistent Peras voting-committee seats a voter receives. It delegates the core Poisson-CDF comparison to `taylorExpCmpFirstNonLower`, which requires `boundX = e^{|x|}` for a mathematically sound error bound. The call site hard-codes `boundX = 3` while passing `x = -lambda`. For any voter whose `lambda > ln(3) ≈ 1.099`, the error bound is **underestimated**, causing the Taylor-series comparison to terminate prematurely and return an inflated seat count. This is the direct analog of the ELO report's "incorrect mathematical constant breaks the formula" class of bug.

---

### Finding Description

The Poisson-CDF seat-count algorithm works as follows:

1. Compute `lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`.
2. Build the lazy `orders` list whose `k`-th element is `(k+1)! * normalizedVRFOutput / lambda^(k+1)`.
3. Call `taylorExpCmpFirstNonLower 3 orders (-lambda)` to find the first index `i` where `orders[i]` is not certainly below `e^{-lambda}`. [1](#0-0) 

Inside `taylorExpCmpFirstNonLower`, the error term at each Taylor step is:

```
errorTerm = abs (err' * boundX)
```

The comment immediately above the function states:

> **IMPORTANT: boundX must be e^{|x|} for correct error bounds.** [2](#0-1) 

Here `x = -lambda`, so the correct `boundX` is `e^lambda`. The call passes the literal `3` instead:

```haskell
taylorExpCmpFirstNonLower
  3          -- ← should be e^lambda
  orders
  (-lambda)
``` [3](#0-2) 

**When `boundX` is too small**, `errorTerm` is too small, so the "certainly BELOW" branch (`cmp < acc' - errorTerm`) fires for values that are actually in the uncertain region. The function skips those thresholds and returns a **larger index**, meaning the voter is awarded **more seats than the correct Poisson-CDF comparison would grant**.

The condition `e^lambda > 3` holds whenever `lambda > ln(3) ≈ 1.099`. `lambda` is:

```
lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake
```

A voter holding ≥ 37 % of the non-persistent stake in a committee with 3 non-persistent voters already exceeds this threshold. Larger committees or higher individual stakes push `lambda` (and thus the error) much higher (e.g., `lambda = 5` → `e^5 ≈ 148`, versus the hard-coded `3`). [4](#0-3) 

---

### Impact Explanation

`localSortitionNumSeats` is called in two production paths:

1. **`implVerifyVote`** — verifies that a non-persistent voter actually holds the seats they claim before accepting their vote.
2. **`implVerifyCert`** — verifies every non-persistent voter in a certificate before accepting the certificate. [5](#0-4) 

When `lambda > ln(3)`, the inflated seat count causes the verifier to accept votes and certificates from non-persistent members who hold **more seats than the Poisson distribution actually grants them**. This directly bypasses the Peras voting-committee eligibility check, allowing a voter to contribute disproportionate voting weight to an election and potentially push a certificate over the quorum threshold with fewer legitimate co-signers than required.

---

### Likelihood Explanation

A non-persistent voter's VRF output is deterministic (it cannot be freely chosen), so the attacker cannot craft an arbitrary output. However:

- The error is **systematic**: every voter with `lambda > ln(3)` is affected on every election, regardless of their VRF output value.
- The condition is **easily met** in realistic committee configurations (e.g., a pool with 40 % of non-persistent stake in a 3-seat non-persistent committee).
- The attacker's entry point is simply **submitting a vote or certificate** as a legitimate non-persistent member; no special network position or key compromise is required.
- The code itself contains a `TODO` acknowledging that the `3` constant has not been validated, confirming the parameter was never formally justified. [6](#0-5) 

---

### Recommendation

Replace the hard-coded `3` with the mathematically correct bound `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} where x = -lambda
      orders
      (-lambda)
```

`exp` on `FixedPoint` is available via `Cardano.Ledger.BaseTypes`. Alternatively, compute a conservative rational upper bound for `e^lambda` using a few terms of its own Taylor series before calling `taylorExpCmpFirstNonLower`.

---

### Proof of Concept

**Setup**: 3 non-persistent voters, voter A holds 50 % of non-persistent stake.

```
lambda = 3 * 0.5 = 1.5
e^lambda = e^1.5 ≈ 4.48   (> 3, so boundX is wrong)
```

**Correct behaviour** (`boundX = e^1.5 ≈ 4.48`):
- `errorTerm` at each step is large enough to keep the comparison in the "uncertain" region until the Taylor series converges.
- Voter A receives the seat count dictated by the true Poisson CDF.

**Buggy behaviour** (`boundX = 3`):
- `errorTerm` is underestimated by factor `4.48/3 ≈ 1.49`.
- The "certainly BELOW" branch fires prematurely for one or more `orders` thresholds.
- `taylorExpCmpFirstNonLower` returns an index one higher than correct.
- Voter A is granted an extra seat, inflating their voting weight.

The verifier in `implVerifyCert` then accepts a certificate built with this inflated seat count, bypassing the Peras quorum check. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L36-62)
```haskell
-- | Compute how many non-persistent seats can be granted by local sortition to
-- a voter given their normalized VRF output and stake
localSortitionNumSeats ::
  -- | Expected number of non-persistent voters in the committee
  NonPersistentCommitteeSize ->
  -- | Total stake of non-persistent voters
  TotalNonPersistentStake ->
  -- | Stake of the voter
  LedgerStake ->
  -- | Normalized VRF output from the participant
  NormalizedVRFOutput ->
  LocalSortitionNumSeats
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-132)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
  a ->
  -- | list of cmp thresholds (checked in order)
  [a] ->
  -- | x in e^x
  a ->
  Maybe Int
taylorExpCmpFirstNonLower boundX cmps x =
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
