### Title
Wrong Taylor-series error bound constant in Peras local sortition seat allocation grants inflated committee seats - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

### Summary

`localSortitionNumSeats` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`, but the function's own contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda` (the Poisson parameter), the correct value is `e^lambda`. For any voter whose `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the algorithm to prematurely declare a Poisson CDF threshold as "not certainly below," granting the voter more non-persistent Peras committee seats than their VRF output actually entitles them to.

### Finding Description

In `localSortitionNumSeats`, the Poisson-based seat count is computed by comparing the voter's normalized VRF output against a sequence of thresholds (`orders`) using a Taylor-series approximation of `e^{-lambda}`:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs, lines 93-99
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3        -- ← hardcoded, but must be e^{|x|} = e^lambda
      orders
      (-lambda)
``` [1](#0-0) 

The `taylorExpCmpFirstNonLower` function's own documentation states the invariant explicitly:

```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term used in the convergence decision is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `boundX < e^lambda`, `errorTerm` is underestimated. The decision logic is:

```haskell
| cmp >= acc' + errorTerm = Stop   -- declares threshold "ABOVE" → grants seats
| cmp < acc' - errorTerm = Below   -- declares threshold "BELOW" → continues
``` [4](#0-3) 

With `errorTerm` too small, the `Stop` (ABOVE) branch fires prematurely: a threshold that is actually above the voter's VRF output is declared "not certainly below," and the voter is granted that many seats. The code itself acknowledges the uncertainty in a TODO comment referencing issue #234, but does not bound or validate `lambda` against the hardcoded constant: [5](#0-4) 

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [6](#0-5) 

This is unbounded above `ln(3) ≈ 1.099`. The `NormalizedVRFOutput` is a `Rational` in `[0, 1]`: [7](#0-6) 

The `localSortitionNumSeats` result is used directly in `implCheckShouldVote` to determine whether a voter is a non-persistent committee member and how many seats they hold: [8](#0-7) 

### Impact Explanation

Any non-persistent voter with `lambda > ln(3) ≈ 1.099` receives an inflated seat count from `localSortitionNumSeats`. Their `LocalSortitionNumSeats` value is used as their voting weight in the Peras committee. Inflated seat counts directly inflate voting power, allowing a voter with minority stake to accumulate disproportionate influence in Peras certificate formation. If enough voters are affected (which is likely in any realistic committee where individual `lambda` values exceed 1.1), the certificate quorum threshold can be met by a coalition that does not actually hold the required stake fraction, constituting a bypass of the Peras voting check.

**Severity: Critical** — maps to "Bypass of Peras voting or certificate checks that enables unauthorized vote or certificate acceptance."

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is triggered for any non-persistent voter whose expected seat count exceeds ~1.1. With a committee of 100 non-persistent voters, any voter holding more than ~1.1% of the non-persistent stake triggers the bug. This is a realistic and common scenario in any non-trivially distributed stake pool set. No special privileges, crafted inputs, or key compromise are required — the bug fires automatically from the voter's own legitimate VRF evaluation.

### Recommendation

Replace the hardcoded `3` with the correct value `e^lambda`. Since `lambda` is a `FixedPoint`, this requires computing `exp lambda` using the same fixed-point arithmetic already available in the module (e.g., via the Taylor expansion itself or an imported `exp` function). The corrected call should be:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

### Proof of Concept

**Setup**: 100 non-persistent voters; one voter holds 5% of non-persistent stake.

- `lambda = 100 * 0.05 = 5.0`
- Correct `boundX = e^5 ≈ 148.41`
- Actual `boundX = 3`
- Underestimation factor: `148.41 / 3 ≈ 49.5×`

**Effect on `decideOne`**: At each Taylor step, `errorTerm = abs(err' * 3)` instead of `abs(err' * 148.41)`. The interval `[acc' - errorTerm, acc' + errorTerm]` is ~49× narrower than it should be. For a VRF output that falls in the true uncertainty interval but outside the shrunken one, the algorithm declares `Stop` (ABOVE) immediately, granting the voter the current seat index rather than continuing to refine. Concretely, a voter whose true Poisson-distributed seat count should be `k` may be granted `k + d` seats (for some `d ≥ 1`) because the algorithm terminates early at a higher threshold. With `lambda = 5`, the expected seat count is 5, but the inflated result can be materially higher, directly amplifying the voter's weight in every Peras election they participate in.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs (L100-103)
```haskell
-- | Normalized VRF outputs as a rational between 0 and 1
newtype NormalizedVRFOutput = NormalizedVRFOutput
  { unNormalizedVRFOutput :: Rational
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-300)
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
```
