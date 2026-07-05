### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Causes Incorrect Local Sortition Seat Counts, Enabling Unauthorized Peras Vote Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` passes the literal constant `3` as the `boundX` (error-bound) parameter to `taylorExpCmpFirstNonLower`, where the function's own contract requires `boundX = e^{|x|}`. Because `x = -lambda`, the correct value is `e^lambda`. Whenever `lambda > ln(3) ≈ 1.099` — a routine condition for any non-trivial committee — the error term is underestimated, the Taylor-series convergence check fires prematurely, and the returned seat count is wrong. Both the voter (forging a vote) and the verifier (`implVerifyVote` / `implVerifyCert`) execute the same broken path, so a voter whose correct seat count is 0 can be granted ≥ 1 seat, and a certificate carrying that inflated seat count passes verification.

---

### Finding Description

`localSortitionNumSeats` implements the local-sortition (LS) component of the wFA^LS Peras voting-committee scheme. It determines how many non-persistent seats a voter is entitled to by comparing the normalized VRF output against Poisson-distribution thresholds via a Taylor-series approximation of `e^{-lambda}`:

```haskell
-- LS.hs lines 94-99
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; should be e^lambda
      orders
      (-lambda)
``` [1](#0-0) 

The helper's own documentation is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

With `x = -lambda`, the required value is `e^lambda`. The hardcoded `3` is correct only when `lambda ≤ ln(3) ≈ 1.099`. For larger `lambda` the error term

```haskell
errorTerm = abs (err' * boundX)   -- boundX = 3, should be e^lambda
``` [3](#0-2) 

is underestimated. The `Stop` (ABOVE) branch

```haskell
| cmp >= acc' + errorTerm = Stop
``` [4](#0-3) 

fires too early, returning a higher index into `orders` than is mathematically justified — i.e., a higher seat count than the voter is entitled to.

The code itself acknowledges the uncertainty with a TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
``` [5](#0-4) 

The comment references `checkLeaderNatValue` in the Ledger, which also uses `3`, but there `3` is the *number of Taylor terms to compute*, not `e^{|x|}` — a categorically different parameter. Copying that literal into a different role is the root cause.

The inflated seat count flows directly into vote-weight computation:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [6](#0-5) 

and into certificate verification:

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
  Just nonZeroNumSeats -> ...
``` [7](#0-6) 

Because both the forger and the verifier call the same `localSortitionNumSeats`, a voter whose correct seat count is 0 computes 1 (or more), forges a vote claiming that count, and the verifier independently recomputes the same wrong value and accepts the vote.

---

### Impact Explanation

**High.** An unprivileged non-persistent committee member whose correct local-sortition result is 0 seats can, when `lambda > ln(3)`, obtain a non-zero seat count from the broken computation. This lets them:

1. Pass the `nonZero numSeats` guard in `implVerifyVote` / `implVerifyCert` that is the sole gate between "ineligible" and "eligible" for non-persistent voters.
2. Contribute inflated vote weight to a Peras certificate.
3. Cause `implVerifyCert` to accept a certificate that should be rejected (or to accept it with a higher quorum contribution than warranted), directly undermining Peras voting and certificate security.

This is a bypass of the local-sortition eligibility check — the Peras analog of the VRF/leader-eligibility bypass in the allowed impact scope.

---

### Likelihood Explanation

**High.** `lambda = numNonPersistentVoters × voterStake / totalNonPersistentStake`. With a committee of 100 non-persistent candidates and a voter holding just 2 % of the non-persistent stake, `lambda = 2 > ln(3) ≈ 1.099`. The error factor is `e^2 / 3 ≈ 2.46×`. Any realistic deployment with more than a handful of non-persistent voters will routinely exceed the threshold. No special privileges, leaked keys, or stake majority are required — only participation as a registered non-persistent voter.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound. Because `lambda` is already a `FixedPoint`, compute `exp lambda` (or a safe rational upper bound) and pass it as `boundX`:

```haskell
-- correct: boundX = e^{|x|} = e^lambda
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- was: 3
      orders
      (-lambda)
```

If `exp` on `FixedPoint` is unavailable, use the same Taylor-series approximation with a conservatively large number of terms, or derive a closed-form upper bound (e.g., `1 + lambda + lambda^2/2 + ...` truncated with a known remainder).

---

### Proof of Concept

**Setup**: 100 non-persistent voters, voter A holds 3 % of non-persistent stake.  
`lambda = 100 × 0.03 = 3.0`  
Correct `boundX = e^3 ≈ 20.09`; actual `boundX = 3`.  
Error-term underestimation factor: `20.09 / 3 ≈ 6.7×`.

**Step 1** — Voter A evaluates their VRF output for election round R. `normalizeVRFOutput` maps it to a rational `v ∈ [0,1]`.

**Step 2** — `orders[0] = v / 3.0`. With the correct `boundX`, the Taylor series for `e^{-3} ≈ 0.0498` would require many more terms before the error bound narrows enough to declare `orders[0]` ABOVE or BELOW. With `boundX = 3`, `errorTerm` is ~6.7× too small; the `Stop` branch fires after far fewer iterations, returning `expectedSeats = 1` for values of `v` where the correct answer is 0.

**Step 3** — Voter A forges `WFALSNonPersistentVote` claiming 1 seat. `implVerifyVote` calls `localSortitionNumSeats` with the same parameters and computes the same wrong value `1`; `nonZero numSeats` succeeds; the vote is accepted.

**Step 4** — `implEligiblePartyVoteWeight` returns `1 × stake / nonPersistentStake` instead of 0, inflating the voter's contribution to any Peras certificate quorum check.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L167-167)
```haskell
    | cmp >= acc' + errorTerm = Stop
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L175-175)
```haskell
    errorTerm = abs (err' * boundX)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L426-429)
```haskell
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
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
