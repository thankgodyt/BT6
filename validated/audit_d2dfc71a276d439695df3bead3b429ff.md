### Title
Hardcoded `boundX = 3` Underestimates Taylor-Series Error Bound in Peras Local Sortition Seat Count, Enabling Incorrect Non-Persistent Voter Eligibility - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Here `x = -lambda` where `lambda = numNonPersistentVoters × voterStake / totalNonPersistentStake`. For any voter with `lambda > ln(3) ≈ 1.099` — a routine condition in production — the error bound is underestimated, causing the Taylor-series comparison to terminate prematurely with a wrong result. This incorrect seat count propagates directly into `implVerifyVote` and `implVerifyCert` in `WFALS.hs`, where it gates acceptance of non-persistent Peras votes and certificates.

---

### Finding Description

`taylorExpCmpFirstNonLower` approximates `e^x` via a Taylor series and compares it against a list of thresholds. The error term at each step is:

```
errorTerm = abs (err' * boundX)          -- LS.hs line 175
```

The comment immediately above the function signature is unambiguous:

> **IMPORTANT: boundX must be e^{|x|} for correct error bounds** [1](#0-0) 

The call site passes the literal `3`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; correct value is exp lambda
      orders
      (-lambda)
``` [2](#0-1) 

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters
    * voterStake
    / totalNonPersistentStake
``` [3](#0-2) 

`3` is a valid upper bound only when `lambda ≤ ln(3) ≈ 1.099`. For larger `lambda`, `e^lambda ≫ 3`, so `errorTerm` is underestimated by a factor of `e^lambda / 3`. With a too-narrow error window, both decision branches fire prematurely:

- `cmp >= acc' + errorTerm` → **ABOVE** (voter granted a seat) fires at a lower threshold than it should
- `cmp < acc' - errorTerm` → **BELOW** (voter denied a seat) fires at a higher threshold than it should [4](#0-3) 

The developers themselves flagged this with a TODO and an open issue:

> TODO(peras): evaluate whether the limit used below (3) makes sense in this context … Tracked by: https://github.com/tweag/cardano-peras/issues/234 [5](#0-4) 

The comparison with `checkLeaderNatValue` (Ledger) is misleading: in that context `|x| = σ · |ln(1−f)| ≤ 1 · 0.051 ≈ 0.051`, so `e^{0.051} ≈ 1.052 < 3` and the constant is safe. In local sortition `|x| = lambda` which can be orders of magnitude larger.

The incorrect seat count is consumed in three production paths in `WFALS.hs`:

1. **`implVerifyVote`** — verifies a non-persistent vote received from a peer: [6](#0-5) 

2. **`implVerifyCert`** — verifies a Peras certificate received from a peer: [7](#0-6) 

3. **`implEligiblePartyVoteWeight`** — computes voting power from the seat count: [8](#0-7) 

The `NormalizedVRFOutput` fed into `localSortitionNumSeats` is derived from a BLS signature hash divided by its maximum value, producing a uniform rational in `[0, 1]`: [9](#0-8) 

---

### Impact Explanation

When `lambda > ln(3)`, the Taylor comparison may terminate before convergence. In the false-positive direction — `orders[k]` declared ABOVE when it is truly BELOW — the voter is granted more seats than their stake warrants. Their voting weight in `implEligiblePartyVoteWeight` is `numSeats × stake / totalNonPersistentStake`, so inflated `numSeats` directly inflates their contribution toward the Peras quorum threshold. In the extreme case, a voter whose VRF output should yield zero seats is instead accepted as a valid non-persistent committee member, constituting a bypass of the Peras voting eligibility check. Both `implVerifyVote` and `implVerifyCert` accept the voter if `nonZero numSeats` is satisfied; an incorrect non-zero result passes that gate unconditionally.

**Impact class:** Critical — bypass of Peras voting or certificate checks that enables unauthorized vote or certificate acceptance.

---

### Likelihood Explanation

`lambda > ln(3)` is the normal operating condition, not an edge case. With a committee of 500 non-persistent seats and a voter holding 1 % of non-persistent stake, `lambda = 5`; `e^5 ≈ 148`, so `boundX` is underestimated by ~49×. With 1000 non-persistent seats and 2 % stake, `lambda = 20`; `e^20 ≈ 485 million`. Any honest node receiving a crafted `WFALSNonPersistentVote` or `WFALSCert` from a peer triggers this path. The attacker does not control the VRF output, but the error is systematic: for any voter whose `(lambda, normalizedVRFOutput)` pair lands in the region where the premature ABOVE decision fires, the incorrect seat count is deterministic and reproducible. The open TODO and linked issue confirm the developers have not yet validated the bound.

---

### Recommendation

Replace the hardcoded `3` with the correct bound derived from `lambda`:

```haskell
-- Correct: boundX = e^{lambda} since x = -lambda
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- was: 3
      orders
      (-lambda)
```

If `exp lambda` is too expensive to compute in `FixedPoint`, a safe conservative integer ceiling (e.g., `ceiling (exp (toRational lambda))`) or a pre-computed lookup table keyed on `lambda` rounded to a small number of bits is acceptable, provided it is always `≥ e^lambda`.

---

### Proof of Concept

**Setup:** Peras epoch with 500 non-persistent committee seats. Voter A holds 2 % of total non-persistent stake.

**Computed lambda:** `lambda = 500 × 0.02 = 10`. Correct `boundX = e^10 ≈ 22026`. Actual `boundX = 3`.

**Error underestimation factor:** `22026 / 3 ≈ 7342×`.

**Scenario:** Voter A's `normalizedVRFOutput` is such that `orders[0]` is slightly below `e^{-10} ≈ 4.54 × 10^{-5}` (voter should get 0 seats). With `boundX = 3`, `errorTerm = |err' × 3|` is far too small; the partial Taylor sum `acc'` has not yet converged to `e^{-10}`, so the condition `cmp >= acc' + errorTerm` fires prematurely, returning index 0 (1 seat) instead of `Nothing` (0 seats).

**Result:** `nonZero numSeats` is satisfied in `implVerifyVote`/`implVerifyCert`; the vote is accepted. Voter A's voting weight is `1 × stake / totalNonPersistentStake = 0.02` instead of 0, contributing toward the Peras quorum threshold without legitimate eligibility. [2](#0-1) [4](#0-3) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-126)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
  a ->
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L348-354)
```haskell
toNormalizedVRFOutput ::
  Signature VRF ->
  NormalizedVRFOutput
toNormalizedVRFOutput sig =
  NormalizedVRFOutput $
    fromIntegral (signatureNatural sig)
      / fromIntegral signatureNaturalMax
```
