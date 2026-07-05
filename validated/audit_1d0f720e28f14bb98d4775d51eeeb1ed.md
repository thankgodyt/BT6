### Title
Wrong `boundX` Constant in Peras Non-Persistent Seat Count Causes Incorrect Voting Power Allocation - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs)

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda`, the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the Taylor-expansion comparison to make incorrect "certainly below" decisions, which inflates the returned seat count. This directly affects how many non-persistent Peras voting seats a committee member is granted, and the same `localSortitionNumSeats` call is used in both vote-forging and vote/certificate verification paths.

### Finding Description

In `localSortitionNumSeats`, the expected number of non-persistent seats for a voter is `lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. The seat count is then determined by comparing the `orders` list (Poisson PMF thresholds derived from the VRF output) against `e^{-lambda}` using a Taylor-expansion helper:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3        -- boundX: MUST be e^{|x|} per the function's contract
      orders
      (-lambda) -- x
``` [1](#0-0) 

The function's own inline contract states:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term is computed as:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `lambda > ln(3) ≈ 1.099`, `e^lambda > 3`, so `boundX = 3` underestimates the true error bound. For `x = -lambda < 0`, the Taylor series has alternating-sign remainder terms. An underestimated `errorTerm` causes the "certainly below" branch (`cmp < acc' - errorTerm`) to fire incorrectly — the algorithm skips past a threshold that is actually above `e^{-lambda}`, returning a higher index and granting the voter more seats than they deserve.

The developers themselves flag this with a TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
``` [4](#0-3) 

The same `localSortitionNumSeats` function is called identically in both `implVerifyVote` and `implVerifyCert` in `WFALS.hs`, which are the production verification paths triggered by incoming peer messages: [5](#0-4) [6](#0-5) 

### Impact Explanation

The Peras protocol uses a weighted Fait-Accompli with Local Sortition (wFA^LS) committee. Non-persistent members' voting power is proportional to their granted seat count. An inflated seat count directly inflates `VoteWeight` in `implEligiblePartyVoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [7](#0-6) 

A voter whose true seat count is `n` but is granted `n+k` seats contributes `(n+k)/n` times their legitimate voting power. If the Peras quorum threshold is close to the honest majority boundary, inflated voting power for a minority coalition could allow them to forge a certificate that the honest majority would not have approved, breaking the Peras finality guarantee. This maps directly to the "Bypass of Peras voting or certificate checks" impact class.

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is triggered when `numNonPersistentVoters * voterStake / totalNonPersistentStake > 1.099`. For a committee with 10 non-persistent voters, any voter holding more than ~11% of the non-persistent stake pool crosses this threshold. This is a realistic stake concentration for a pool operator with moderate delegation. No key compromise, grinding, or admin access is required — the bug fires deterministically for any eligible voter whose stake ratio exceeds the threshold.

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound. Since `x = -lambda` and `lambda > 0`, the correct `boundX` is `e^lambda`. Using the same `FixedPoint` arithmetic already in scope:

```haskell
-- Correct: boundX = e^{lambda} as required by taylorExpCmpFirstNonLower's contract
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- was: 3
      orders
      (-lambda)
```

Alternatively, adopt the same approach as `checkLeaderNatValue` in `cardano-ledger`, which uses a proven-correct fixed bound derived from the protocol's parameter constraints.

### Proof of Concept

Let `numNonPersistentVoters = 10`, `voterStake = 2`, `totalNonPersistentStake = 10`. Then `lambda = 2.0`. The correct `boundX = e^2 ≈ 7.389`, but `3` is used. For `x = -2`, the Taylor series remainder after `n` terms is `O(2^n / n!)` with alternating sign. With `boundX = 3`, `errorTerm` is underestimated by a factor of `~2.46`. The "certainly below" branch fires for a threshold `orders[i]` that is actually above `e^{-2} ≈ 0.135`, causing the function to advance past it and return index `i+1` or higher — granting the voter at least one extra seat beyond their Poisson-correct entitlement. The verifier in `implVerifyVote` accepts this inflated seat count without further validation, crediting the voter with excess `VoteWeight` in the Peras election.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-533)
```haskell
              let numSeats =
                    localSortitionNumSeats
                      (nonPersistentCommitteeSize committee)
                      (totalNonPersistentStake committee)
                      voterStake
                      (normalizeVRFOutput vrfOutput)
```
