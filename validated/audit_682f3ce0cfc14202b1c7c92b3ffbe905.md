### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Violates Its Own Error-Bound Contract, Producing Wrong Non-Persistent Seat Counts for High-Stake Voters - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own documentation states **"IMPORTANT: boundX must be e^{|x|} for correct error bounds"**. The actual argument is `x = -lambda`, so the correct bound is `e^lambda`. For any voter whose `lambda > ln(3) ≈ 1.099`, the supplied bound is strictly smaller than required, making the Taylor-series error term too tight. This causes the comparison to prematurely declare a threshold "ABOVE" or "BELOW" before the series has converged, yielding an incorrect seat count. Because the same function is used symmetrically by both the voter (`implCheckShouldVote`) and the verifier (`implVerifyVote`, `implVerifyCert`), both sides compute the same wrong count, so the error is accepted as valid by the protocol.

---

### Finding Description

`taylorExpCmpFirstNonLower` approximates `e^x` via a Taylor series and compares it against a list of thresholds. The `errorTerm` at each step is:

```haskell
errorTerm = abs (err' * boundX)   -- LS.hs line 175
```

The comment at line 121 is explicit:

> IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).

The call site in `localSortitionNumSeats` is:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded, not e^lambda
      orders
      (-lambda)  -- x = -lambda
``` [1](#0-0) 

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [2](#0-1) 

`lambda` is unbounded above `ln(3)`. With 100 non-persistent voters, any voter holding more than ~1.1 % of the non-persistent stake produces `lambda > ln(3)`. A voter with 10 % stake gives `lambda = 10`, so the correct bound is `e^10 ≈ 22 026`, yet `3` is supplied — an underestimate by a factor of ~7 300.

When `boundX` is too small, `errorTerm` is too small. The decision logic:

```haskell
| cmp >= acc' + errorTerm = Stop   -- declared ABOVE (returns this index)
| cmp < acc' - errorTerm  = Below  -- declared BELOW (advances to next)
| otherwise               = decideOne ...
``` [3](#0-2) 

…collapses the "uncertain" band prematurely. A threshold that is genuinely uncertain (the series has not converged) is forced into either ABOVE or BELOW, producing a seat count that differs from the mathematically correct Poisson-CDF result.

The incorrect seat count propagates through every path that calls `localSortitionNumSeats`:

- **`implCheckShouldVote`** — voter self-assessment of eligibility [4](#0-3) 
- **`implVerifyVote`** — per-vote verification [5](#0-4) 
- **`implVerifyCert`** — certificate verification [6](#0-5) 

Because both sides use the same broken function, the wrong seat count is accepted as legitimate by every verifier.

The `orders` thresholds are derived from the voter's normalized VRF output:

```haskell
orders =
  (fromRational normalizedVRFOutput / lambda)
    : zipWith (\k prev -> k * prev / lambda) [2 ..] orders
``` [7](#0-6) 

The VRF output is pseudorandom but deterministic per election. For elections where the premature convergence fires in the "ABOVE" direction, the voter receives more seats than the Poisson distribution entitles them to, inflating their voting weight in the Peras committee.

The code itself acknowledges the `3` is unvalidated:

> TODO(peras): evaluate whether the limit used below (3) makes sense in this context. [8](#0-7) 

---

### Impact Explanation

An incorrect seat count in the Peras/Leios non-persistent committee directly affects voting power (`implEligiblePartyVoteWeight` scales stake by `numSeats`). [9](#0-8)  When the error inflates a voter's seat count, that voter casts votes with more weight than their ledger stake justifies, bypassing the stake-proportional security assumption of the Peras voting/certificate checks. A certificate forged with inflated-weight votes passes `implVerifyCert` because the verifier recomputes the same wrong seat count. This constitutes unauthorized certificate acceptance under the allowed impact scope.

---

### Likelihood Explanation

The condition `lambda > ln(3)` is met by any non-persistent voter whose proportional stake exceeds `ln(3) / numNonPersistentVoters`. With a committee of 100 non-persistent voters this threshold is ~1.1 %; with 50 voters it is ~2.2 %. In realistic stake distributions, multiple voters will exceed this threshold in every epoch, making the incorrect computation a routine occurrence rather than an edge case.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound. Since `x = -lambda` and `lambda > 0`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

If `FixedPoint` does not support `exp` directly, compute a rational upper bound on `e^lambda` using the same Taylor-series infrastructure, or clamp `lambda` to a safe maximum and document the constraint.

---

### Proof of Concept

**Setup**: 100 non-persistent voters; one voter holds 10 % of non-persistent stake.

```
lambda = 100 * 0.10 = 10
correct boundX = e^10 ≈ 22026
supplied boundX = 3
```

At Taylor step `n`, `err' ≈ lambda^n / n!` (for `x = -lambda`). The correct `errorTerm` at step 5 is:

```
|err'| * e^10 ≈ (10^5/120) * 22026 ≈ 18 355 000
```

The supplied `errorTerm`:

```
|err'| * 3 ≈ (10^5/120) * 3 ≈ 2 500
```

The algorithm treats the series as converged ~7 300× too early. For a VRF output whose normalized value places `orders[1]` within the collapsed "uncertain" band, the algorithm fires `Stop` at index 1 (granting 1 seat) when the correct answer is 0 seats, or fires `Stop` at index 2 (granting 2 seats) when the correct answer is 1 seat. The verifier accepts the inflated seat count because it runs the identical broken computation.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L75-81)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L165-169)
```haskell
  decideOne maxN n err acc divisor cmp
    | maxN == n = Stop
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
    | otherwise = decideOne maxN (n + 1) err' acc' divisor' cmp
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-291)
```haskell
          let numSeats =
                localSortitionNumSeats
                  (nonPersistentCommitteeSize committee)
                  (totalNonPersistentStake committee)
                  ourStake
                  (normalizeVRFOutput vrfOutput)
          case nonZero numSeats of
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-384)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L421-432)
```haskell
  WFALSNonPersistentMember
    _seatIndex
    (LedgerStake stake)
    _vrfOutput
    numSeats ->
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
     where
      TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
        totalNonPersistentStake committee
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-536)
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
```
