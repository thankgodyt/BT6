### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Violates Its Own Precondition, Corrupting Non-Persistent Committee Seat Counts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`, but the function's own documented precondition requires `boundX = e^{|x|}`. Because `x = -lambda` and `lambda` grows with voter stake and committee size, any voter with `lambda > ln(3) ≈ 1.099` receives an underestimated error bound. This causes the Taylor-series convergence check to terminate early with an incorrect seat count, which propagates directly into the voter's `VoteWeight` in the Peras committee.

---

### Finding Description

`taylorExpCmpFirstNonLower` is a Taylor-expansion comparator that approximates `e^x` and decides whether a threshold `cmp` is above or below the approximation. Its error term is:

```haskell
errorTerm = abs (err' * boundX)   -- LS.hs line 175
```

The inline comment at line 121 is unambiguous:

> **IMPORTANT: boundX must be e^{|x|} for correct error bounds**

The call site in `localSortitionNumSeats` passes `x = -lambda` and hardcodes `boundX = 3`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded, must be e^lambda
      orders
      (-lambda)  -- ← x
``` [1](#0-0) 

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [2](#0-1) 

`boundX = 3` is only a valid bound when `lambda ≤ ln(3) ≈ 1.099`. For any voter where `lambda > 1.099`, `3 < e^lambda`, so `errorTerm` is underestimated. The convergence check in `decideOne` then uses a window that is too narrow:

```haskell
| cmp >= acc' + errorTerm = Stop          -- declared ABOVE (voter gets a seat)
| cmp < acc' - errorTerm  = Below ...     -- declared BELOW (voter gets no seat)
| otherwise               = recurse
``` [3](#0-2) 

When `errorTerm` is too small, borderline cases that should remain uncertain are prematurely classified. In the ABOVE direction, a voter is granted a seat they may not be entitled to. The codebase itself acknowledges the problem with a TODO:

> TODO(peras): evaluate whether the limit used below (3) makes sense in this context … Tracked by https://github.com/tweag/cardano-peras/issues/234 [4](#0-3) 

The contrast with the ledger's `checkLeaderNatValue` (which also uses `3`) is instructive: there `x = -sigma * ln(1-f)` with `sigma ≤ 1` and `f = 0.05`, giving `|x| ≤ 0.051` and `e^{0.051} ≈ 1.05`, so `3` is a safe over-approximation. In `localSortitionNumSeats`, `lambda` is unbounded above `1.099` for any voter with meaningful stake in a realistically-sized committee.

---

### Impact Explanation

The inflated `expectedSeats` value flows directly into `implVerifyVote` in `WFALS.hs`:

```haskell
let numSeats =
      localSortitionNumSeats
        (nonPersistentCommitteeSize committee)
        (totalNonPersistentStake committee)
        voterStake
        (normalizeVRFOutput vrfOutput)
case nonZero numSeats of
  Nothing -> Left (ZeroNonPersistentSeats seatIndex)
  Just nonZeroNumSeats ->
    pure $ WFALSNonPersistentMember seatIndex voterStake vrfOutput nonZeroNumSeats
``` [5](#0-4) 

The accepted `nonZeroNumSeats` is then used to compute `VoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake / nonPersistentStake
``` [6](#0-5) 

An inflated seat count directly inflates the voter's `VoteWeight`, giving them disproportionate influence over Peras certificate formation. A voter with `lambda` significantly above `1.099` can receive one or more extra seats, materially weakening the stake-proportional authorization guarantee of the wFA^LS committee selection scheme.

**Impact: Medium** — materially weakens vote authorization for non-persistent committee members without requiring DoS.

---

### Likelihood Explanation

For a committee with `numNonPersistentVoters = N`, the threshold is `voterStake / totalNonPersistentStake > 1.099 / N`. With `N = 100` (a plausible Peras committee size), any voter holding more than ~1.1% of the non-persistent stake is affected. On a realistic stake distribution with hundreds of pools, a large fraction of non-persistent candidates will exceed this threshold. The bug is triggered on every vote verification for such voters — no special crafting is required beyond submitting a legitimate vote.

**Likelihood: High**

---

### Recommendation

Replace the hardcoded `3` with the correct bound derived from `lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp (realToFrac lambda))   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

Alternatively, clamp `lambda` to a maximum value consistent with `boundX = 3` (i.e., `lambda ≤ ln 3`) and document the restriction explicitly, though this would incorrectly deny seats to high-stake voters.

---

### Proof of Concept

Consider:
- `numNonPersistentVoters = 100`
- `voterStake / totalNonPersistentStake = 0.05` (5% of non-persistent stake)
- `lambda = 100 * 0.05 = 5.0`
- Correct `boundX = e^5 ≈ 148.4`; used `boundX = 3`

At each Taylor step, `errorTerm = |err' * 3|` instead of `|err' * 148.4|`. The error window is ~50× too narrow. For a `cmp` value that falls within the true error band but outside the underestimated band, `decideOne` returns `Stop` (ABOVE) after far fewer iterations than required, granting the voter a seat that the correct computation would have left undecided or denied. With `lambda = 5`, the Poisson distribution has non-negligible mass at 4, 5, 6, and 7 seats, so the incorrect early termination can shift the seat count by one or more units, inflating `VoteWeight` by `stake / nonPersistentStake` per extra seat.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L426-429)
```haskell
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
```
