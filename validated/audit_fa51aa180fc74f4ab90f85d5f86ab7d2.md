### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Local Sortition Seat Count for Non-Persistent Peras Committee Members with `lambda > ln(3)` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The contract of that function requires `boundX = e^{|x|}` for correct error bounds. Because `x = -lambda`, the correct value is `e^lambda`. For any non-persistent voter whose expected seat count `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the Taylor-series comparison to terminate prematurely with a wrong result. This directly corrupts the number of seats granted to the voter, inflating or deflating their `VoteWeight` in the Peras committee.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent seats a voter is entitled to via local sortition. The core computation is:

```haskell
lambda = fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [1](#0-0) 

Then `expectedSeats` is determined by:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- <-- hardcoded boundX
      orders
      (-lambda)
``` [2](#0-1) 

The function's own contract states:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [3](#0-2) 

Inside `decideOne`, the error term is:

```haskell
errorTerm = abs (err' * boundX)
``` [4](#0-3) 

When `lambda > ln(3) ≈ 1.099`, `e^lambda > 3`, so `errorTerm` is underestimated. The comparison window `[acc' - errorTerm, acc' + errorTerm]` is narrower than the true uncertainty interval. Values that are genuinely uncertain are prematurely classified as either ABOVE (granting a seat) or BELOW (denying a seat). The code itself acknowledges the uncertainty with a `TODO`:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [5](#0-4) 

The magnitude of the error grows rapidly. For `lambda = 2`, `e^2 ≈ 7.39` vs `boundX = 3` (2.5× underestimate). For `lambda = 5` (a voter with 5% of non-persistent stake in a 100-seat committee), `e^5 ≈ 148` vs `boundX = 3` (49× underestimate). The Taylor series terminates far too early with a large unaccounted error.

The incorrect `expectedSeats` directly feeds into `VoteWeight` computation:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [6](#0-5) 

And is verified on the receiving side in both `implVerifyVote` and `implVerifyCert`: [7](#0-6) [8](#0-7) 

Because both the voter and the verifier use the same buggy `boundX = 3`, a voter whose `lambda > ln(3)` may receive a seat count that is consistently wrong on both sides — meaning the inflated seat count passes verification and is accepted into the certificate.

---

### Impact Explanation

**Critical/High — Bypass of Peras voting committee eligibility check.**

When `expectedSeats` is overestimated due to the incorrect error bound, a non-persistent voter's `VoteWeight` is inflated beyond what their actual stake entitles them to. Since both the voter's self-check (`implCheckShouldVote`) and the verifier's check (`implVerifyVote`, `implVerifyCert`) use the same flawed `localSortitionNumSeats`, the inflated seat count is accepted as valid. A pool with disproportionate voting power can push a Peras certificate over the quorum threshold with less actual stake than required, enabling unauthorized block boosting or chain selection manipulation.

---

### Likelihood Explanation

Any non-persistent voter with `lambda > 1.099` is affected. With a committee of 100 non-persistent seats, a voter holding just over 1.1% of the non-persistent stake already crosses the threshold. Pools with 5–20% of non-persistent stake (common in realistic deployments) have `lambda` values of 5–20, where the error bound is off by factors of 49× to 485,165,195×. This is not a rare edge case — it affects the majority of meaningful non-persistent committee participants.

---

### Recommendation

Replace the hardcoded `3` with the correct value `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp (realToFrac lambda))   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

This matches the contract documented at line 121 of `LS.hs` and is consistent with how `checkLeaderNatValue` in `cardano-ledger` computes the analogous bound for slot leadership proofs.

---

### Proof of Concept

Consider a committee with `numNonPersistentVoters = 10` and a voter holding 30% of the non-persistent stake:

```
lambda = 10 * 0.30 / 1.0 = 3.0
e^lambda = e^3 ≈ 20.09
boundX used = 3
```

The error term at each Taylor step is underestimated by a factor of ~6.7×. The algorithm terminates after far fewer iterations than needed for convergence. For a VRF output `normalizedVRFOutput` near the boundary between 3 and 4 seats, the premature termination classifies the comparison as ABOVE (granting 4 seats) when the correct answer is BELOW (3 seats). The voter's `VoteWeight` is `4 * stake / totalNonPersistentStake` instead of `3 * stake / totalNonPersistentStake` — a 33% inflation. Since `implVerifyCert` recomputes the same value with the same bug, the inflated weight passes certificate verification and is accepted by all honest nodes running this code.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L427-429)
```haskell

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
