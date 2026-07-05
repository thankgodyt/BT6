### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Inflates Peras Non-Persistent Committee Seat Count - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3` instead of the mathematically required `e^lambda`. The function's own contract states `boundX` must equal `e^{|x|}` for correct error bounds. When `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the Taylor-expansion comparison to prematurely declare a Poisson threshold as exceeded, granting a non-persistent Peras committee voter more seats than their stake entitles them to. Since `implVerifyVote` and `implVerifyCert` in `WFALS.hs` call the same function to verify eligibility, all nodes accept the inflated seat count, systematically over-weighting votes from any voter whose `lambda` exceeds `ln(3)`.

---

### Finding Description

In `localSortitionNumSeats`, the number of non-persistent committee seats is determined by comparing a normalized VRF output against Poisson distribution thresholds via a Taylor-expansion convergence test:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- hardcoded; should be exp lambda
      orders
      (-lambda)
``` [1](#0-0) 

The `taylorExpCmpFirstNonLower` function's contract is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Since `x = -lambda`, the correct value is `boundX = e^lambda`. The hardcoded `3` is only a valid upper bound when `lambda ≤ ln(3) ≈ 1.099`. For any voter with `lambda > ln(3)`, `e^lambda > 3`, so the error term `abs(err' * boundX)` in `decideOne` is smaller than required:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

A smaller `errorTerm` makes the ABOVE condition (`cmp >= acc' + errorTerm`) easier to satisfy, causing the algorithm to prematurely return a higher seat index — i.e., grant more seats than the voter's stake warrants.

The codebase itself acknowledges the `3` is unvalidated:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
``` [4](#0-3) 

---

### Impact Explanation

`localSortitionNumSeats` is called in three security-critical paths in `WFALS.hs`:

1. **`implCheckShouldVote`** — determines whether a node is eligible to vote and how many seats it holds.
2. **`implVerifyVote`** — verifies an incoming vote's eligibility before accepting it.
3. **`implVerifyCert`** — verifies each voter's eligibility when validating a Peras certificate. [5](#0-4) [6](#0-5) [7](#0-6) 

Because all nodes run the same buggy code, the inflated seat count is computed identically by both the voter and every verifier. The inflated `numSeats` directly multiplies the voter's `VoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [8](#0-7) 

A voter whose `lambda > ln(3)` systematically receives inflated voting weight in every Peras election round. Enough such voters could collectively reach the quorum stake threshold with less actual stake than the protocol requires, enabling unauthorized Peras certificate acceptance and chain-weight manipulation.

---

### Likelihood Explanation

`lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. With a non-persistent committee of ~1000 voters (a plausible Peras parameter), any voter holding more than ~0.11% of total non-persistent stake has `lambda > ln(3)`. This threshold is reachable by any moderately-sized stake pool without requiring a stake majority, leaked keys, or operator compromise. The attacker-controlled entry path is simply submitting a `WFALSNonPersistentVote` with a VRF output that, under the correct error bound, would yield fewer seats — but under the buggy bound, yields more.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

This ensures the Taylor-expansion error bound is tight and correct for all values of `lambda`, matching the contract documented in `taylorExpCmpFirstNonLower`.

---

### Proof of Concept

Consider a non-persistent committee of 1000 voters where a single voter holds 0.2% of total non-persistent stake:

- `lambda = 1000 * 0.002 = 2.0`
- Correct `boundX = e^2.0 ≈ 7.389`
- Hardcoded `boundX = 3`

In `decideOne`, `errorTerm = abs(err' * 3)` instead of `abs(err' * 7.389)`. The error band is 2.46× narrower than required. For a VRF output that sits between the correct seat-1 and seat-2 Poisson thresholds, the algorithm may declare ABOVE at seat-2 (granting 2 seats) when the correct answer is 1 seat. The voter's `VoteWeight` is then doubled relative to their actual stake entitlement. Across multiple such voters in a round, the effective quorum threshold is materially weakened, allowing a Peras certificate to be forged with less aggregate stake than the `perasQuorumStakeThreshold` requires.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L38-47)
```haskell
localSortitionNumSeats ::
  -- | Expected number of non-persistent voters in the committee
  NonPersistentCommitteeSize ->
  -- | Total stake of non-persistent voters
  TotalNonPersistentStake ->
  -- | Stake of the voter
  LedgerStake ->
  -- | Normalized VRF output from the participant
  NormalizedVRFOutput ->
  LocalSortitionNumSeats
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L86-89)
```haskell
    -- TODO(peras): evaluate whether the limit used below (3) makes sense in
    -- this context. One possible starting point would be to understand why
    -- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
    -- computing slot leadership proofs.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L426-429)
```haskell
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
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
