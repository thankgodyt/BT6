Now I have a complete picture. Let me verify the exact line numbers and the call sites.### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Invalidates Error Bounds for `lambda > ln(3)`, Enabling Incorrect Non-Persistent Seat Count - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3` to compute the number of Peras voting seats granted to a non-persistent committee member via local sortition. The function's contract requires `boundX = e^{|x|}` for mathematically correct error bounds. Because `x = -lambda` and `lambda` routinely exceeds `ln(3) ≈ 1.099` for any voter with meaningful stake in a realistically-sized committee, the error bound is systematically underestimated. This causes the Taylor-expansion comparison to terminate with an incorrect result, granting a voter more seats than their VRF output and stake entitle them to. The same `localSortitionNumSeats` call is the sole gate used by `implVerifyVote` and `implVerifyCert` in `WFALS.hs` to authorize non-persistent vote and certificate acceptance.

---

### Finding Description

`taylorExpCmpFirstNonLower` approximates `e^x` via a Taylor series and uses `errorTerm = abs(err' * boundX)` as the Lagrange remainder bound to decide whether a comparison threshold is definitively above or below `e^x`. The function's own documentation states:

> `IMPORTANT: boundX must be e^{|x|} for correct error bounds` [1](#0-0) 

The call site in `localSortitionNumSeats` passes `x = -lambda` and hardcodes `boundX = 3`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- should be e^lambda
      orders
      (-lambda)
``` [2](#0-1) 

The correct value is `e^lambda`. `boundX = 3` is only valid when `lambda ≤ ln(3) ≈ 1.099`.

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [3](#0-2) 

For a committee with 500 non-persistent voters, any voter holding more than `ln(3)/500 ≈ 0.22%` of the total non-persistent stake produces `lambda > ln(3)`. This covers virtually every voter with any meaningful stake.

When `boundX < e^lambda`, the `errorTerm` in `decideOne` is too small:

```haskell
errorTerm = abs (err' * boundX)   -- underestimated when boundX < e^lambda
``` [4](#0-3) 

The Taylor partial sums for `e^{-lambda}` (with `lambda > 0`) alternate in sign and oscillate around the true value. When the partial sum overshoots above `e^{-lambda}`, the lower confidence bound `acc' - errorTerm` can exceed `e^{-lambda}` if `errorTerm` is too small. A threshold `cmp` (= `orders[k]`) satisfying `e^{-lambda} ≤ cmp < acc' - errorTerm` is then classified as `Below` (line 168) when it is actually `Above`, causing the algorithm to skip past a true stopping point and return a higher seat index — i.e., more seats than the voter is entitled to.

The code itself acknowledges the problem with an open TODO:

> `TODO(peras): evaluate whether the limit used below (3) makes sense in this context.`
> Tracked by: https://github.com/tweag/cardano-peras/issues/234 [5](#0-4) 

---

### Impact Explanation

`localSortitionNumSeats` is the sole eligibility gate for non-persistent Peras committee members. Its result is used directly in three places in `WFALS.hs`:

1. **`implCheckEligibility`** — determines whether a node may forge a vote at all. [6](#0-5) 
2. **`implVerifyVote`** — verifies an incoming non-persistent vote. [7](#0-6) 
3. **`implVerifyCert`** — verifies a non-persistent voter's contribution inside a certificate. [8](#0-7) 

The `numSeats` value returned by `localSortitionNumSeats` is stored in the `WFALSNonPersistentMember` witness and later used by `implEligiblePartyVoteWeight` to compute the voter's effective voting power:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake / nonPersistentStake
``` [9](#0-8) 

An inflated `numSeats` directly multiplies the voter's effective stake contribution. A non-persistent voter whose true Poisson draw entitles them to `k` seats but who receives `k + d` seats due to the incorrect error bound gains `d * stake / nonPersistentStake` extra voting weight. If this inflated weight tips the quorum threshold, the node accepts a Peras certificate — and the boosted block it attests — that should not have reached quorum. This is a bypass of the local sortition eligibility check, constituting unauthorized certificate acceptance.

---

### Likelihood Explanation

The condition `lambda > ln(3)` is satisfied by essentially every non-persistent voter with any meaningful stake in a realistically-sized committee. For a 500-seat committee with 200 non-persistent seats, a voter holding 1% of the non-persistent stake has `lambda = 2`, already nearly double `ln(3)`. The bug is not gated by any adversarial precondition: it is triggered by normal participation. Any node that receives a vote or certificate from such a voter and calls `implVerifyVote` or `implVerifyCert` is affected. The entry path requires no special privileges — only a valid VRF key and stake, both of which are normal prerequisites for committee participation.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp (toRational lambda))   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

Since `FixedPoint` may not expose `exp` directly, compute the bound in `Rational` or `Double` before passing it in, consistent with how `normalizedVRFOutput` is already handled via `fromRational`. Alternatively, use the same vendored Taylor-expansion infrastructure to compute `e^lambda` to sufficient precision before the comparison loop. The open issue https://github.com/tweag/cardano-peras/issues/234 should be resolved before this code is used in production.

---

### Proof of Concept

**Setup:** Committee with 500 non-persistent voters. Voter A holds 2% of total non-persistent stake.

**Computed lambda:** `lambda = 500 * 0.02 = 10.0`

**Correct `boundX`:** `e^10 ≈ 22026`

**Actual `boundX`:** `3` (underestimate by factor ~7342)

**Effect on `errorTerm`:** At Taylor iteration `n`, `errorTerm = |err_n| * 3` instead of `|err_n| * 22026`. The error bound is ~7342× too small.

**Consequence:** The Taylor partial sums for `e^{-10} ≈ 0.0000454` oscillate with large amplitude before converging. With `errorTerm` underestimated by ~7342×, the algorithm prematurely classifies a threshold `orders[k]` as `Below` when the partial sum overshoots above `e^{-10}` and `acc' - errorTerm` still exceeds `orders[k]`. The algorithm skips past the true stopping point and returns a higher seat count. Voter A's `numSeats` is inflated, their `VoteWeight` is proportionally inflated, and any certificate they contribute to is accepted with an overstated quorum contribution — bypassing the local sortition seat bound that the Peras protocol relies on for security.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L94-99)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-301)
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
                    nonZeroNumSeats
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
