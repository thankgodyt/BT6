### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Violates Its Own Contract, Producing Incorrect Non-Persistent Seat Counts in Peras Voting Committee - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` passes the literal `3` as the `boundX` argument to `taylorExpCmpFirstNonLower`. The function's own inline contract states **"IMPORTANT: boundX must be e^{|x|} for correct error bounds"**. Since `x = -lambda`, the correct value is `e^lambda`. For any voter whose expected seat count `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the Taylor-series comparison to produce an incorrect `expectedSeats` value. This incorrect count is then used verbatim in `implVerifyVote` and `implVerifyCert` to accept or reject non-persistent Peras votes and certificates.

---

### Finding Description

`localSortitionNumSeats` computes the number of non-persistent Peras committee seats for a voter via a Poisson-distribution comparison:

```haskell
-- LS.hs lines 65-99
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake

orders :: [FixedPoint]
orders =
  (fromRational normalizedVRFOutput / lambda)
    : zipWith (\k prev -> k * prev / lambda) [2 ..] orders

expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- <-- hardcoded boundX
      orders
      (-lambda)
```

The helper `taylorExpCmpFirstNonLower` approximates `e^x` (here `x = -lambda`) via a Taylor series and compares each partial sum against the `orders` thresholds. Its error term is:

```haskell
-- LS.hs line 175
errorTerm = abs (err' * boundX)
```

The comment at line 121 is unambiguous:

> **IMPORTANT: boundX must be e^{|x|} for correct error bounds.**

Because `x = -lambda`, the correct `boundX` is `e^lambda`. The code passes `3` unconditionally. This is only correct when `lambda = ln 3 ≈ 1.099`.

**When `lambda > ln 3`:** `e^lambda > 3`, so `errorTerm` is underestimated. The algorithm becomes overconfident: it declares a threshold "ABOVE" (`Stop`) or "BELOW" with less evidence than required. Concretely, the condition

```haskell
cmp >= acc' + errorTerm  -- Stop: e^x is above this threshold
```

fires at a lower bar than it should, causing `expectedSeats` to be inflated for voters whose `lambda` is large. Conversely, the "BELOW" branch can fire prematurely, causing legitimate seats to be denied.

The TODO comment in the same block (lines 86–92) explicitly acknowledges that the value `3` has not been validated for this context and is tracked as an open issue (`https://github.com/tweag/cardano-peras/issues/234`).

The incorrect `expectedSeats` propagates directly into vote and certificate verification:

- **`implVerifyVote`** (WFALS.hs lines 375–390): calls `localSortitionNumSeats`; if `numSeats = 0` the vote is rejected with `ZeroNonPersistentSeats`; if `numSeats` is inflated the `WFALSNonPersistentMember` witness carries the wrong seat count.
- **`implVerifyCert`** (WFALS.hs lines 528–543): same call path; an inflated `numSeats` is embedded in the returned `EligibilityWitness`.
- **`implEligiblePartyVoteWeight`** (WFALS.hs lines 426–429): vote weight is `numSeats * stake / nonPersistentStake`; inflated `numSeats` directly inflates voting power.

---

### Impact Explanation

A non-persistent committee member whose `lambda > ln 3` (i.e., whose expected seat count exceeds ~1.1) receives an incorrect seat count from `localSortitionNumSeats`. In the inflation direction, their `VoteWeight` is proportionally overstated. In a committee with 100 non-persistent voters, any voter holding more than ~1.1 % of total non-persistent stake is affected. For a voter with 5 % stake, `lambda = 5` and `e^lambda ≈ 148` versus the hardcoded `3`—a 49× underestimate of the error bound. The inflated vote weight could allow a minority-stake coalition to reach the Peras quorum threshold and forge a certificate that would not be valid under correct arithmetic, constituting a bypass of Peras voting committee eligibility checks.

---

### Likelihood Explanation

The condition `lambda > ln 3` is met by any non-persistent voter whose stake fraction exceeds `ln(3) / numNonPersistentVoters`. For a realistic committee of 100 non-persistent voters this threshold is ~1.1 %, a stake level easily held by a single mid-sized pool. No special privileges beyond normal pool operation are required; the attacker simply participates in elections as a non-persistent member.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `exp lambda` (computed as a `FixedPoint`):

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

If computing `exp lambda` is too expensive, a conservative upper bound (e.g., the ceiling of `e^lambda` for the maximum expected `lambda`) may be used, but it must never be less than `e^lambda`.

---

### Proof of Concept

**Setup**: Peras committee with 100 non-persistent voters; attacker controls a pool with 5 % of total non-persistent stake.

**Computation**:
- `lambda = 100 × 0.05 = 5.0`
- Correct `boundX = e^5 ≈ 148.41`
- Actual `boundX = 3`
- `errorTerm` underestimated by factor ≈ 49.5

**Effect**: `decideOne` fires `Stop` (declares `e^{-lambda}` is above a threshold) with an error window 49× too narrow. For a VRF output near a threshold boundary, the algorithm returns `expectedSeats = k+1` when the correct answer is `k`, granting the attacker one extra seat. Their `VoteWeight` becomes `(k+1) × stake / nonPersistentStake` instead of `k × stake / nonPersistentStake`. `implVerifyCert` accepts the certificate with this inflated weight, and the Peras quorum check uses the wrong total.

**Relevant code locations**: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L426-432)
```haskell
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
     where
      TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
        totalNonPersistentStake committee
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
