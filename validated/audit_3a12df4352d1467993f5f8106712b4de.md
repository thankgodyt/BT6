### Title
Incorrect Taylor Series Error Bound Constant in Local Sortition Seat Count Causes Incorrect Peras Vote Weight - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`, but the function's own contract requires `boundX = e^{|x|}`. Since `x = -lambda`, the correct bound is `e^lambda`. For any non-persistent committee voter whose expected seat count `lambda > ln(3) ≈ 1.099` — i.e., any voter with more than ~1.1× the average non-persistent stake — the error bound is underestimated. This causes the Taylor series convergence check to make premature decisions, producing an incorrect seat count. The seat count directly determines the voter's `VoteWeight` in `implEligiblePartyVoteWeight`, and the same incorrect formula is used in both `implVerifyVote` and `implVerifyCert`, meaning an inflated seat count is accepted by verifiers.

---

### Finding Description

**Root cause — `LS.hs` lines 94–99:**

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; must be e^lambda per the function contract
      orders
      (-lambda)
```

The function's own contract is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  -- | boundX = e^{|x|} for correct error estimation
  a ->
```

`x = -lambda`, so `|x| = lambda`, and `boundX` must be `e^lambda`. The hardcoded `3` equals `e^lambda` only when `lambda = ln(3) ≈ 1.099`. For any voter with `lambda > 1.099`, `e^lambda > 3` and the bound is too small.

**How `lambda` is computed (lines 65–70):**

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
```

`lambda` is the voter's proportional share of non-persistent seats. A voter with 2× average non-persistent stake has `lambda = 2`; `e^2 ≈ 7.39`, not `3`. A voter with 3× average stake has `lambda = 3`; `e^3 ≈ 20.09`, not `3`.

**How the underestimated `errorTerm` corrupts the decision (lines 165–175):**

```haskell
| cmp >= acc' + errorTerm = Stop   -- "proven ABOVE" → return current index
| cmp < acc' - errorTerm  = Below  -- "proven BELOW" → advance to next threshold
| otherwise = decideOne ...        -- uncertain → iterate
errorTerm = abs (err' * boundX)
```

With `boundX` too small, `errorTerm` is smaller than the true Taylor remainder. The "proven ABOVE" band (`acc' + errorTerm`) shrinks, so the algorithm declares convergence prematurely for thresholds that are actually within the true error margin. This can return an index (seat count) that is higher than the mathematically correct value.

**The TODO comment in the code itself acknowledges the problem (lines 86–92):**

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. One possible starting point would be to understand why
-- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
-- computing slot leadership proofs.
--
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
```

The value `3` was copied from the Praos slot-leadership check (`checkLeaderNatValue`), where `x = -sigma * ln(1-f)` and `|x|` is typically very small (well below `ln(3)`). In the local sortition context, `lambda` can be much larger, making the copied constant incorrect.

**Downstream impact — vote weight inflation (`WFALS.hs` lines 426–429):**

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
```

An inflated `numSeats` directly multiplies the voter's stake to produce their `VoteWeight`. The same `localSortitionNumSeats` call appears in `implVerifyVote` (lines 375–380) and `implVerifyCert` (lines 528–533), so verifiers accept the inflated weight.

---

### Impact Explanation

**Impact: High — Bypass of Peras voting/certificate checks.**

A non-persistent committee member with `lambda > ln(3)` (above-average non-persistent stake) may receive more seats than the protocol specifies. Their `VoteWeight` is proportionally inflated. If the inflation is sufficient to push a certificate over the quorum threshold that would otherwise not be reached, the result is unauthorized certificate acceptance — a Peras safety failure. The same incorrect formula is used in both forging and verification paths, so the inflated weight passes all on-chain checks.

---

### Likelihood Explanation

**Likelihood: Medium.**

Any non-persistent voter with more than ~1.1× the average non-persistent stake has `lambda > ln(3)`. In a realistic committee with heterogeneous stake distribution, multiple voters will exceed this threshold in every epoch. The incorrect seat count only materializes when the voter's normalized VRF output falls within the Taylor series error margin near a Poisson CDF threshold — a probabilistic event the voter cannot control. However, the condition `lambda > ln(3)` is routinely satisfied, and the error grows with `lambda` (e.g., factor of ~6.7× underestimate at `lambda = 3`), making incorrect decisions increasingly likely for high-stake voters.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound `e^lambda`:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

This matches the documented contract of `taylorExpCmpFirstNonLower` and eliminates the precision loss for all values of `lambda`. The existing `lambda <= 0` guard already prevents division-by-zero, so no additional guards are needed.

---

### Proof of Concept

**Setup:** Non-persistent committee with 100 voters, equal stake. One voter has 3× average stake: `voterStake / totalNonPersistentStake = 3/100`, `numNonPersistentVoters = 100`, so `lambda = 3`.

**Correct bound:** `e^3 ≈ 20.09`. `errorTerm = |err' * 20.09|`.

**Actual bound used:** `3`. `errorTerm = |err' * 3|` — underestimated by factor ~6.7.

**Consequence:** At Taylor iteration `n`, the partial sum `acc'` approximates `e^{-3} ≈ 0.0498`. The true remainder is bounded by `|err'| * 20.09`, but the code uses `|err'| * 3`. For a threshold `cmp` satisfying `acc' + |err'|*3 <= cmp < acc' + |err'|*20.09`, the code declares "proven ABOVE" (returns current index as seat count) while the true value of `e^{-3}` is still below `cmp`. This grants the voter one additional seat beyond what the Poisson distribution specifies, inflating their `VoteWeight` by `1 * stake / nonPersistentStake`.

The entry path is: a crafted `WFALSNonPersistentVote` or `WFALSCert` from a non-persistent voter with above-average stake, processed by `implVerifyVote` or `implVerifyCert` in `WFALS.hs`, which calls `localSortitionNumSeats` in `LS.hs` at lines 375–380 and 528–533 respectively. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L64-70)
```haskell
    -- Expected number of seats granted by local sortition
    lambda :: FixedPoint
    lambda =
      fromRational $
        fromIntegral numNonPersistentVoters
          * voterStake
          / totalNonPersistentStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L86-99)
```haskell
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
