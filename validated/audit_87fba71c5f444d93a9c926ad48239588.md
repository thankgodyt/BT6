### Title
Incorrect `boundX` Constant in `taylorExpCmpFirstNonLower` Causes Unreliable Committee Eligibility Decisions - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own documentation states `boundX` **must** equal `e^{|x|}` for the error bound to be mathematically correct. Because `x = -lambda` and `lambda` can exceed `ln(3) ≈ 1.099` in realistic committee configurations, the error term is underestimated, causing the Taylor-expansion comparison to terminate prematurely with an incorrect result. This can grant non-persistent committee seats to ineligible voters or deny them to eligible ones — directly bypassing the Peras voting committee eligibility check.

---

### Finding Description

In `localSortitionNumSeats`, the number of non-persistent seats a voter is entitled to is determined by comparing `e^{-lambda}` against a list of Poisson CDF thresholds (`orders`) using `taylorExpCmpFirstNonLower`:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- boundX = 3  ← hardcoded, WRONG when lambda > ln(3)
      orders
      (-lambda)
``` [1](#0-0) 

The function's contract is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term used to decide whether the partial Taylor sum has converged is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

With `x = -lambda` (lambda > 0), the mathematically correct `boundX` is `e^lambda`. The hardcoded value `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. For larger `lambda`, `errorTerm` is underestimated, so the convergence window `[acc' - errorTerm, acc' + errorTerm]` is too narrow. The comparison may fire the "ABOVE" branch (`cmp >= acc' + errorTerm`) prematurely, returning `Just i` (granting `i` seats) when the true answer is `Nothing` (zero seats). The code itself acknowledges the value is unvalidated:

```haskell
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [4](#0-3) 

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [5](#0-4) 

For a committee with 100 non-persistent voters and a pool holding 2% of non-persistent stake, `lambda = 2.0 > ln(3)`. For 50 voters and 5% stake, `lambda = 2.5`. These are realistic production values.

---

### Impact Explanation

`localSortitionNumSeats` is called in both **vote verification** (`implVerifyVote`) and **certificate verification** (`implVerifyCert`):

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
    pure $ WFALSNonPersistentMember ...
``` [6](#0-5) [7](#0-6) 

When the incorrect `boundX` causes a false non-zero seat count, a voter whose VRF output should yield zero seats passes the `nonZero numSeats` check and is accepted as a valid non-persistent committee member. Their vote is counted toward quorum and certificate formation. This is a **bypass of Peras voting committee eligibility**, allowing an unauthorized pool to influence or forge a Peras certificate.

---

### Likelihood Explanation

The bug is triggered whenever `lambda > ln(3) ≈ 1.099`. Lambda equals `numNonPersistentVoters × (voterStake / totalNonPersistentStake)`. Any pool with more than ~1.1% of non-persistent stake in a committee of 100 non-persistent voters, or more than ~2.2% in a committee of 50, exceeds this threshold. This covers the vast majority of meaningful stake pools in a production Peras deployment. The adversary does not need to control their VRF output — they only need their VRF output to land in the region where the underestimated error bound causes a false positive, which is a non-negligible probability for borderline cases.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

Since `FixedPoint` supports `exp` (or it can be approximated conservatively), this is a direct fix. Alternatively, use a conservative upper bound that is proven safe for all valid `lambda` values, with a documented proof analogous to the approach recommended in the external report.

---

### Proof of Concept

Consider:
- `numNonPersistentVoters = 10`
- `voterStake / totalNonPersistentStake = 0.2` → `lambda = 2.0`
- Correct `boundX = e^2.0 ≈ 7.389`; used `boundX = 3`

At Taylor order `n`, `errorTerm = |err' * 3|` instead of `|err' * 7.389|`. The convergence window is 2.46× too narrow. For a VRF output `normalizedVRFOutput` near `lambda * e^{-lambda} ≈ 2 * 0.135 = 0.271` (the boundary of the first Poisson threshold), the comparison `e^{-lambda} >= orders[0]` falls inside the true uncertainty interval but outside the underestimated one. The function returns `Just 0` (1 seat granted) when the correct answer is `Nothing` (0 seats). The vote from this pool passes `implVerifyVote` and is counted toward a Peras certificate. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-392)
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
    | otherwise ->
        Left (NotANonPersistentMember seatIndex)
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
