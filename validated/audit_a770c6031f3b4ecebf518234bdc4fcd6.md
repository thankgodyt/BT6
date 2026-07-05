### Title
Incorrect `boundX` Parameter in Taylor-Series Error Bound Causes Wrong Peras Committee Seat Count - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own documentation mandates `boundX = e^{|x|}` for a valid error bound. Because `x = -lambda` (where `lambda > 0`), the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the supplied bound is too small, the Taylor-series remainder is underestimated, and the algorithm makes premature convergence decisions — producing an incorrect seat count. This is the direct analog of the FairSide arctan bug: a mathematical formula is implemented with a wrong constant in place of a value that must depend on the input, causing incorrect results for a reachable input range.

---

### Finding Description

`taylorExpCmpFirstNonLower` approximates `e^x` via a Taylor series and compares it against a list of thresholds. Its first parameter, `boundX`, is used to bound the Taylor remainder:

```
errorTerm = abs(err' * boundX)
```

The remainder bound for the Taylor series of `e^x` truncated at term `N` is:

```
|R_N(x)| ≤ |x^{N+1} / (N+1)!| · e^{|x|}
```

The code computes `err' = x^{N+1} / (N+1)!` (the next term), so `boundX` must satisfy `boundX ≥ e^{|x|}` for `errorTerm` to be a valid upper bound on the remainder. The comment at line 121 states this requirement explicitly:

> `-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).`

The call site in `localSortitionNumSeats` is:

```haskell
taylorExpCmpFirstNonLower
  3          -- boundX  ← hardcoded constant
  orders
  (-lambda)  -- x
```

Here `x = -lambda`, so `|x| = lambda`, and the correct `boundX` is `e^lambda`. The hardcoded `3` is only a valid bound when `e^lambda ≤ 3`, i.e., `lambda ≤ ln(3) ≈ 1.099`.

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters
    * voterStake
    / totalNonPersistentStake
```

With a non-persistent committee of, say, 100 voters, any pool holding more than ~1.1 % of the non-persistent stake produces `lambda > ln(3)`. This is a routine operating condition, not an edge case.

When `boundX < e^lambda`, `errorTerm` is underestimated. The algorithm becomes overconfident: it may classify a threshold as `ABOVE` (granting seats) or `BELOW` (denying seats) before the partial sum has converged to the true value of `e^{-lambda}`. The resulting `expectedSeats` value is incorrect. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

`localSortitionNumSeats` is called in three places in `WFALS.hs`:

1. **`implCheckEligibility`** — a pool checks its own eligibility to vote.
2. **`implVerifyVote`** — a node verifies a non-persistent voter's vote received from a peer.
3. **`implVerifyCert`** — a node verifies a Peras certificate received from a peer. [4](#0-3) [5](#0-4) 

In `implVerifyVote` and `implVerifyCert`, if `localSortitionNumSeats` returns a non-zero value for a voter whose true seat count is zero (false positive due to premature `ABOVE` decision), the vote or certificate is accepted despite the voter being ineligible. This constitutes a **bypass of Peras non-persistent committee membership verification**: an unauthorized vote or certificate is accepted by an honest node.

Conversely, a false negative (premature `BELOW` decision) causes a legitimate voter's contribution to be rejected, breaking Peras quorum formation.

The security-critical direction is the false positive: an ineligible pool operator can have their votes and certificates accepted by all honest nodes, directly undermining the Peras voting and certificate authorization checks.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met whenever:

```
numNonPersistentVoters * voterStake / totalNonPersistentStake > 1.099
```

With a non-persistent committee of 100 members, any pool with more than ~1.1 % of the non-persistent stake is affected. With 500 members, the threshold drops to ~0.22 %. These are realistic stake fractions for active Cardano stake pools. The condition is not adversarially crafted — it arises from ordinary stake distribution and committee sizing. Every node independently computes the same incorrect seat count, so the error is consistent across the network (it does not cause a split), but it systematically misauthorizes or rejects votes for all pools above the threshold.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound `e^lambda`. Since `lambda` is a `FixedPoint`, an approximation sufficient to bound `e^lambda` is needed. The upstream `cardano-ledger` `NonIntegral` module already provides a `taylorExpCmp` that takes the correct bound; the fix is to pass `exp lambda` (or a safe upper-bound approximation thereof) as `boundX`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

If `exp` is not available for `FixedPoint`, a conservative integer upper bound (e.g., `ceiling (exp (toRational lambda))`) suffices, as `boundX` only needs to be an upper bound, not exact. [6](#0-5) 

---

### Proof of Concept

Consider a Peras committee with `numNonPersistentVoters = 100` and a pool holding 2 % of non-persistent stake (`voterStake / totalNonPersistentStake = 0.02`):

```
lambda = 100 * 0.02 = 2.0
e^lambda = e^2 ≈ 7.389
```

The code passes `boundX = 3`, but the correct bound is `7.389`. The error term at each Taylor step is underestimated by a factor of `7.389 / 3 ≈ 2.46×`. The algorithm may stop after, say, 3 terms when the partial sum `1 - 2 + 2 = 1` has not yet converged to `e^{-2} ≈ 0.135`. At that point, `acc' = 1` and `errorTerm = abs((-2)^3/6 * 3) = abs(-4/3) ≈ 1.33`. The condition `cmp >= acc' + errorTerm` evaluates as `orders[0] >= 1 + 1.33 = 2.33`. With the correct bound, `errorTerm = abs((-2)^3/6 * 7.389) ≈ 3.28`, giving `cmp >= 1 + 3.28 = 4.28` — a much stricter threshold that correctly defers the decision. The premature stop with `boundX = 3` can classify a threshold as `ABOVE` when the true `e^{-2} ≈ 0.135` is far below it, granting the pool seats it does not deserve. A peer sending a vote with this pool's VRF output would pass `implVerifyVote`'s seat-count check on every honest node. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L157-175)
```haskell
  decideOne ::
    Int -> -- maxN
    Int -> -- n
    a -> -- err
    a -> -- acc
    a -> -- divisor
    a -> -- cmp
    Step a
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-540)
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
```
