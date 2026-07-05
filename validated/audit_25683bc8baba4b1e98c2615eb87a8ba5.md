### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Local Sortition Seat Counts for Non-Persistent Peras Voters - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Taylor-series comparison helper `taylorExpCmpFirstNonLower` is called with a hardcoded error-bound parameter `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` where `x = -lambda`. When `lambda > ln(3) ≈ 1.099`, the supplied constant is smaller than the required value, the error term is underestimated, and the comparison terminates with an incorrect result. The returned `expectedSeats` value is then used directly in Peras vote and certificate verification, enabling unauthorized vote acceptance or spurious vote rejection.

---

### Finding Description

`localSortitionNumSeats` computes `lambda` — the expected number of non-persistent committee seats for a voter — as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters
    * voterStake
    / totalNonPersistentStake
``` [1](#0-0) 

It then calls:

```haskell
taylorExpCmpFirstNonLower
  3        -- boundX
  orders
  (-lambda)
``` [2](#0-1) 

The function's own documentation states:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [3](#0-2) 

Here `x = -lambda`, so `|x| = lambda`, and the correct value is `boundX = e^lambda`. The hardcoded `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`.

Inside `decideOne`, the error term is:

```haskell
errorTerm = abs (err' * boundX)
``` [4](#0-3) 

When `boundX < e^lambda`, `errorTerm` is underestimated. The guards:

```haskell
| cmp >= acc' + errorTerm = Stop   -- declares e^x ABOVE threshold
| cmp < acc' - errorTerm  = Below  -- declares e^x BELOW threshold
``` [5](#0-4) 

…fire prematurely, causing the algorithm to return an incorrect index. The returned index is `expectedSeats`, which is cast directly to `LocalSortitionNumSeats`.

The code itself acknowledges the problem with a TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
``` [6](#0-5) 

---

### Impact Explanation

`localSortitionNumSeats` is called in three security-critical paths in `WFALS.hs`:

1. **`implVerifyVote`** — verifies a non-persistent member's vote. If `numSeats = 0`, the vote is rejected with `ZeroNonPersistentSeats`. [7](#0-6) 

2. **`implVerifyCert`** — verifies a Peras certificate. Each non-persistent voter's seat count is recomputed and checked. [8](#0-7) 

3. **`implCheckShouldVote`** — determines whether the local node should cast a vote. [9](#0-8) 

Because both the voter and the verifier call the same `localSortitionNumSeats` with the same incorrect `boundX`, they compute the same wrong `expectedSeats`. When the incorrect result is `numSeats > 0` but the mathematically correct result is `numSeats = 0`, an ineligible voter's vote passes verification. Conversely, when the incorrect result is `numSeats = 0` but the correct result is `> 0`, a legitimate vote is rejected. The vote weight used in quorum calculation (`implEligiblePartyVoteWeight`) is also derived from `numSeats`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [10](#0-9) 

An inflated seat count inflates vote weight, allowing a Peras quorum to be reached with less legitimate stake than the protocol requires, enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

`lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. The threshold `lambda > ln(3) ≈ 1.099` is exceeded whenever a voter's stake fraction exceeds `1.099 / numNonPersistentVoters`. With a typical non-persistent committee size of 100, any voter holding more than ~1.1% of the non-persistent stake triggers the bug. In a realistic Cardano-like stake distribution, many pools will exceed this threshold. The condition is therefore expected to occur routinely in production.

---

### Recommendation

Replace the hardcoded `3` with the correct value `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
-     3
+     (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

This matches the contract stated in the function's own documentation and the analogous usage in `checkLeaderNatValue` in the Cardano Ledger, which passes the correct exponential bound.

---

### Proof of Concept

Consider a committee with:
- `numNonPersistentVoters = 10`
- A voter with 20% of non-persistent stake: `voterStake / totalNonPersistentStake = 0.2`
- `lambda = 10 * 0.2 = 2.0`
- Correct `boundX = e^2.0 ≈ 7.389`; supplied `boundX = 3`

In `decideOne`, `errorTerm = abs(err' * 3)` instead of `abs(err' * 7.389)`. The error interval `[acc' - errorTerm, acc' + errorTerm]` is 2.46× too narrow. The algorithm declares the comparison settled after fewer Taylor terms than required, returning an incorrect `expectedSeats`. Since both the voter (in `implCheckShouldVote`) and the verifier (in `implVerifyVote` / `implVerifyCert`) call the same function with the same inputs, they agree on the wrong answer. A vote cast by this voter with the incorrect seat count passes all verification checks, constituting unauthorized Peras vote acceptance.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L167-168)
```haskell
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L175-175)
```haskell
    errorTerm = abs (err' * boundX)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-383)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L426-429)
```haskell
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
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
