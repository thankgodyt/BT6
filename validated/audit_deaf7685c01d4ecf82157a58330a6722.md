### Title
Incorrect `boundX` Constant in `taylorExpCmpFirstNonLower` Breaks Peras Local Sortition Seat-Count Invariant — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` passes the hardcoded literal `3` as the `boundX` argument to `taylorExpCmpFirstNonLower`. The function's own contract states **"IMPORTANT: boundX must be e^{|x|} for correct error bounds"**. The actual argument `x` is `-lambda` (where `lambda > 0`), so the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the Taylor-expansion comparison to prematurely declare a threshold comparison as "certain" when it is not. This can grant a non-persistent Peras committee member more (or fewer) voting seats than their VRF output actually entitles them to, breaking the seat-count invariant that gates vote and certificate acceptance.

---

### Finding Description

`localSortitionNumSeats` implements the local-sortition (LS) component of the wFA^LS Peras voting-committee scheme. It determines how many non-persistent seats a voter is entitled to by comparing their normalized VRF output against Poisson-CDF thresholds via a Taylor-expansion approximation of `e^{-lambda}`:

```haskell
-- LS.hs lines 93-99
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; should be e^lambda
      orders
      (-lambda)
``` [1](#0-0) 

The `taylorExpCmpFirstNonLower` function computes the error term as:

```haskell
errorTerm = abs (err' * boundX)   -- line 175
``` [2](#0-1) 

For the Taylor series of `e^x`, the remainder after `n` terms is bounded by `|x^{n+1}/(n+1)!| * e^{|x|}`. The term `err'` already carries `x^{n+1}/(n+1)!`, so `boundX` must equal `e^{|x|} = e^lambda` to produce a valid error bound. The hardcoded `3` is only correct when `lambda ≤ ln(3) ≈ 1.099`.

The code itself acknowledges the uncertainty with an open TODO:

```haskell
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. One possible starting point would be to understand why
-- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
-- computing slot leadership proofs.
--
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [3](#0-2) 

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [4](#0-3) 

For a committee with 100 non-persistent voters, any voter holding more than ~1.1 % of the non-persistent stake produces `lambda > ln(3)`. At `lambda = 5` (5 % stake, 100 voters), `e^lambda ≈ 148`, so the error bound is underestimated by a factor of ~49. The comparison can prematurely declare a threshold as "certainly above" or "certainly below" `e^{-lambda}`, yielding a wrong seat count.

The result of `localSortitionNumSeats` is consumed directly in both the vote-forging path and the vote/certificate verification path:

```haskell
-- WFALS.hs: implVerifyVote, line 375-383
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
``` [5](#0-4) 

If `localSortitionNumSeats` returns a non-zero value when the correct computation would return zero, `implVerifyVote` accepts the vote. The same pattern appears in `implVerifyCert`: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer that is a non-persistent committee candidate can submit a Peras vote whose VRF output, under the incorrect error bound, causes `localSortitionNumSeats` to return ≥ 1 seat when the mathematically correct result is 0. The vote passes `implVerifyVote`'s eligibility check and is accepted. Aggregated into a certificate via `implVerifyCert`, this constitutes unauthorized Peras certificate acceptance — a bypass of the Peras voting/certificate authorization check. Conversely, the same arithmetic error can deny seats to legitimate voters, suppressing valid votes and potentially preventing quorum.

**Impact class**: Critical — bypass of Peras voting committee authorization enabling unauthorized vote and certificate acceptance.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met whenever a voter's share of non-persistent stake exceeds `ln(3) / numNonPersistentVoters`. For a committee of 100 non-persistent voters this is ~1.1 %, a threshold routinely exceeded by mid-sized stake pools. The error grows rapidly with `lambda`: at `lambda = 3`, `e^lambda / 3 ≈ 6.7×`; at `lambda = 5`, `≈ 49×`. The code's own open TODO (issue #234) confirms the authors are aware the constant is unvalidated.

---

### Recommendation

Replace the hardcoded `3` with the correct upper bound `e^lambda`:

```haskell
import Cardano.Ledger.BaseTypes (fpExp)   -- or equivalent

expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (fpExp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

Alternatively, follow the same approach used by `checkLeaderNatValue` in `cardano-ledger` and verify that the chosen constant is provably sufficient for all reachable `lambda` values, documenting the proof inline and closing issue #234.

---

### Proof of Concept

```
Given:
  numNonPersistentVoters = 100
  voterStake             = 0.05   (5 % of non-persistent stake)
  totalNonPersistentStake = 1.0

  lambda = 100 * 0.05 / 1.0 = 5.0
  correct boundX = e^5 ≈ 148.41
  actual  boundX = 3

  errorTerm underestimated by factor ≈ 49.5

For a normalizedVRFOutput value v such that the correct seat count is 0
(i.e., orders[0] = v/lambda < e^{-lambda}), the underestimated errorTerm
can cause the condition

  cmp >= acc' + errorTerm

to fire prematurely (Stop → seat count = 1) before enough Taylor terms
have been accumulated to establish that orders[0] < e^{-5}.

Concretely: at n=1, acc' ≈ 1 + (-5) = -4, err' ≈ 25/2 = 12.5,
errorTerm = 12.5 * 3 = 37.5.  If orders[0] ≥ -4 + 37.5 = 33.5 the
function returns Stop (seat = 1).  With the correct boundX = 148.41,
errorTerm = 12.5 * 148.41 = 1855, so the same orders[0] value would
not trigger Stop and the function would continue iterating to the
correct result of 0 seats.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-548)
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
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)
```
