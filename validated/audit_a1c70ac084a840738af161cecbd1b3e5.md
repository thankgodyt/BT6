### Title
Incorrect `boundX` Constant in `taylorExpCmpFirstNonLower` Causes Incorrect Non-Persistent Seat Count, Enabling Unauthorized Peras Vote Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own documentation states `boundX` **must** equal `e^{|x|}` for correct error bounds. The actual `x` passed is `-lambda`, so the correct bound is `e^lambda`. For any voter with `lambda > ln(3) ≈ 1.099` (i.e., any non-trivial stakeholder in a moderately-sized non-persistent committee), the error bound is underestimated, causing the Taylor-series comparison to terminate prematurely with an incorrect seat count. This is used directly in vote and certificate verification (`implVerifyVote`, `implVerifyCert`), meaning an ineligible non-persistent voter can have their vote accepted.

---

### Finding Description

In `localSortitionNumSeats`, the number of non-persistent seats a voter is entitled to is computed by comparing a normalized VRF output against Poisson CDF thresholds via a Taylor-series approximation:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- <-- hardcoded boundX
      orders
      (-lambda)  -- <-- x = -lambda
``` [1](#0-0) 

The `taylorExpCmpFirstNonLower` function's documented precondition is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Since `x = -lambda`, the correct `boundX` is `e^lambda`. The hardcoded value `3` is only valid when `lambda < ln(3) ≈ 1.099`. `lambda` is computed as:

```haskell
lambda = fromRational $ fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [3](#0-2) 

For a committee with 100 non-persistent candidates and a voter holding 5% of non-persistent stake, `lambda = 5`, giving `e^lambda ≈ 148.4`. The hardcoded `3` underestimates the error bound by a factor of ~50.

The error term used in the comparison is:

```haskell
errorTerm = abs (err' * boundX)
``` [4](#0-3) 

With `boundX` too small, `errorTerm` is underestimated, causing the "definitely ABOVE" condition (`cmp >= acc' + errorTerm`) to trigger prematurely. The algorithm returns a non-zero seat index before the Taylor series has converged, producing a falsely elevated seat count.

The code itself acknowledges this is unresolved:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. One possible starting point would be to understand why
-- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
-- computing slot leadership proofs.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [5](#0-4) 

The value `3` was copied from `checkLeaderNatValue` in the Ledger, where `|x| = sigma * |ln(1-f)| < 0.1` for typical Cardano parameters, making `3` a safe overestimate there. In local sortition, `lambda` can be orders of magnitude larger, making `3` a severe underestimate.

---

### Impact Explanation

`localSortitionNumSeats` is called in three places in `WFALS.hs`:

1. **`implVerifyVote`** — verifies a non-persistent member's vote:

```haskell
let numSeats = localSortitionNumSeats ... (normalizeVRFOutput vrfOutput)
case nonZero numSeats of
  Nothing -> Left (ZeroNonPersistentSeats seatIndex)
  Just nonZeroNumSeats -> pure $ WFALSNonPersistentMember ...
``` [6](#0-5) 

2. **`implVerifyCert`** — verifies a certificate's non-persistent voters: [7](#0-6) 

3. **`implEligiblePartyVoteWeight`** — computes voting power proportional to `numSeats`: [8](#0-7) 

When `boundX` is too small, a voter whose VRF output should yield 0 seats (ineligible for this election) may be computed as having ≥1 seats. Their vote passes `implVerifyVote` and their certificate passes `implVerifyCert`. Additionally, inflated `numSeats` directly inflates `VoteWeight`, allowing a voter to contribute disproportionate stake toward quorum.

**Impact class:** Bypass of Peras voting committee eligibility checks enabling unauthorized vote and certificate acceptance, and inflated voting power for non-persistent committee members.

---

### Likelihood Explanation

Any pool operator who is a non-persistent committee candidate can trigger this. No special privileges are required beyond normal pool operation. The condition `lambda > ln(3)` is met whenever a voter holds more than `ln(3)/numNonPersistentVoters ≈ 1.1%` of the non-persistent stake in a committee of 100 non-persistent candidates — a routine scenario. The exact VRF output values that produce a false positive depend on the specific lambda, but the boundary region where the Taylor series is undecided (and the incorrect bound causes a wrong answer) is non-negligible for large lambda. The developers themselves have flagged this as an open correctness concern (issue #234).

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

Since `lambda` is already a `FixedPoint`, an appropriate fixed-point exponential (or a sufficiently conservative upper bound derived from the actual range of `lambda`) should be used. Alternatively, cap `lambda` at a known maximum and use `e^{lambda_max}` as a static bound.

---

### Proof of Concept

Consider a non-persistent committee with `numNonPersistentVoters = 100` and a voter holding 5% of non-persistent stake:

- `lambda = 100 * 0.05 / 1.0 = 5.0`
- Correct `boundX = e^5 ≈ 148.4`; actual `boundX = 3`
- `x = -5.0`; `e^x ≈ 0.00674`

The Taylor series for `e^{-5}` requires many terms to converge. With `errorTerm` underestimated by ~50×, the `decideOne` loop hits the `cmp >= acc' + errorTerm` branch after only a few iterations, returning `Stop` (ABOVE) prematurely. For a VRF output whose true Poisson probability places the voter below the 1-seat threshold, the function returns `Just 0` (1 seat) instead of `Nothing` (0 seats). The adversary submits a vote with this VRF output; `implVerifyVote` calls `localSortitionNumSeats` with the same incorrect bound and accepts the vote, granting the adversary unauthorized participation in the Peras voting round.

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
