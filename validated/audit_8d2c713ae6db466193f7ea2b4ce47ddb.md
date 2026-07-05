### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Taylor Error Bounds for `lambda > ln(3)`, Enabling Inflated Non-Persistent Voting Seat Grants - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. The actual argument is `x = -lambda`, so the correct bound is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the hardcoded `3 < e^lambda`, the error term is underestimated, and the Taylor convergence check terminates prematurely with a wrong seat count. This is directly analogous to the Liquidswap bug: an incorrect constant in a consensus-critical arithmetic computation causes incorrect validation results.

---

### Finding Description

`taylorExpCmpFirstNonLower` computes a Taylor-series approximation of `e^x` and compares it against a list of thresholds. Its first parameter is documented as:

> `-- IMPORTANT: boundX must be e^{|x|} for correct error bounds`
> `-- | boundX = e^{|x|} for correct error estimation` [1](#0-0) 

The error term used to decide convergence is:

```haskell
errorTerm = abs (err' * boundX)
``` [2](#0-1) 

The convergence decision is:

```haskell
| cmp >= acc' + errorTerm = Stop   -- declared ABOVE (seat granted)
| cmp < acc' - errorTerm  = Below  -- declared BELOW (seat denied)
| otherwise               = decideOne ...  -- continue iterating
``` [3](#0-2) 

In `localSortitionNumSeats`, the call is:

```haskell
taylorExpCmpFirstNonLower
  3          -- boundX: WRONG when lambda > ln(3)
  orders
  (-lambda)
``` [4](#0-3) 

Here `x = -lambda`, so the correct `boundX` is `e^lambda`. The value `3` is only a valid upper bound when `lambda ≤ ln(3) ≈ 1.099`. When `lambda > 1.099`, `3 < e^lambda`, `errorTerm` is underestimated, and the "uncertain" convergence zone is narrower than it should be. The algorithm then prematurely declares ABOVE or BELOW for thresholds that are actually within the true uncertainty interval.

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [5](#0-4) 

`lambda > ln(3)` is easily reached in practice. For example, with 10 non-persistent voters and a voter holding 15% of non-persistent stake, `lambda = 1.5 > 1.099`. With 5 non-persistent voters and 25% stake, `lambda = 1.25 > 1.099`.

The codebase itself acknowledges the problem with a TODO:

> `-- TODO(peras): evaluate whether the limit used below (3) makes sense in this context.`
> `-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234` [6](#0-5) 

---

### Impact Explanation

`localSortitionNumSeats` is called in two security-critical paths in `WFALS.hs`:

1. **`implVerifyVote`** — verifying a non-persistent vote received from a peer: [7](#0-6) 

2. **`implVerifyCert`** — verifying a Peras certificate received from a peer: [8](#0-7) 

The returned `numSeats` directly controls the vote weight assigned in `implEligiblePartyVoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake / nonPersistentStake
``` [9](#0-8) 

When `lambda > ln(3)` and the VRF output lands near a threshold boundary, the algorithm may prematurely declare ABOVE, granting the voter one or more extra seats. This inflates their `VoteWeight` beyond what the protocol allows. With inflated weight, a non-persistent voter can contribute more stake toward the quorum threshold than they legitimately hold, potentially enabling a certificate to be forged and accepted with fewer actual votes than required. This constitutes a bypass of Peras voting committee seat verification and unauthorized certificate acceptance.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is reachable with ordinary stake distributions. Any non-persistent voter holding more than `ln(3) / numNonPersistentVoters` of the non-persistent stake triggers the bug. With a committee of 10 non-persistent voters, any voter with more than ~11% of non-persistent stake is affected. This is a realistic stake concentration for a production Cardano pool. No special privileges, key compromise, or majority stake are required — only a valid non-persistent committee membership and a VRF output that falls in the incorrectly-narrowed convergence zone.

---

### Recommendation

Replace the hardcoded `3` with the correct `e^lambda` bound. Since `lambda` is a `FixedPoint`, compute `exp lambda` using the available fixed-point arithmetic and pass it as `boundX`:

```haskell
taylorExpCmpFirstNonLower
  (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
  orders
  (-lambda)
```

This matches the documented contract of `taylorExpCmpFirstNonLower` and eliminates the premature convergence for all values of `lambda`.

---

### Proof of Concept

**Setup:** 10 non-persistent voters; attacker holds 20% of non-persistent stake.

- `lambda = 10 * 0.20 = 2.0`
- Correct `boundX = e^2.0 ≈ 7.389`; actual `boundX = 3`
- `errorTerm` is underestimated by factor `≈ 2.46×`

**Trigger:** Attacker submits a `WFALSNonPersistentVote` with a VRF output `v` such that `normalizedVRFOutput / lambda` falls in the interval `[acc' + errorTerm_wrong, acc' + errorTerm_correct)` for the first threshold in `orders`. With the wrong bound, `decideOne` fires `Stop` (ABOVE) prematurely, granting the attacker 1 seat when the correct answer is 0.

**Effect:** `implVerifyVote` returns `WFALSNonPersistentMember` with `numSeats = 1` instead of rejecting with `ZeroNonPersistentSeats`. The attacker's `VoteWeight` is set to `1 * stake / nonPersistentStake = 0.20` instead of `0`. Repeated across multiple elections where the VRF output lands in the vulnerable zone, the attacker accumulates inflated vote weight toward the quorum threshold, enabling certificate acceptance with fewer legitimate votes than the protocol requires.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-126)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
  a ->
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L165-169)
```haskell
  decideOne maxN n err acc divisor cmp
    | maxN == n = Stop
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
    | otherwise = decideOne maxN (n + 1) err' acc' divisor' cmp
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L174-175)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-546)
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
```
