### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Taylor Error Bound, Enabling Unauthorized Non-Persistent Committee Seat Grant - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for a valid error bound. Because `x = -lambda` and `lambda` can exceed `ln(3) ≈ 1.099` for any voter with non-trivial stake in a large non-persistent pool, the error term is systematically underestimated. This causes the Taylor-expansion comparison to terminate early with an incorrect result, which can grant a non-persistent voter more seats than their VRF output entitles them to. The same `localSortitionNumSeats` call is the sole eligibility gate in both `implVerifyVote` and `implVerifyCert` in `WFALS.hs`, so a false-positive seat count bypasses the local-sortition check and causes an unauthorized vote or certificate to be accepted.

---

### Finding Description

`taylorExpCmpFirstNonLower` computes a Taylor-series approximation of `e^x` and uses an error term to decide, for each comparison threshold, whether the true value is certainly above or certainly below the threshold:

```
errorTerm = abs (err' * boundX)
```

The comment on the parameter is unambiguous:

> `-- | boundX = e^{|x|} for correct error estimation`
> `-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).`

The call site in `localSortitionNumSeats` passes `x = -lambda` but supplies `boundX = 3` unconditionally:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← should be e^lambda, not 3
      orders
      (-lambda)
```

`lambda` is:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
```

For any committee with `numNonPersistentVoters ≥ 2` and a voter holding more than `ln(3)/numNonPersistentVoters` of the non-persistent stake, `lambda > ln(3) ≈ 1.099`, so `e^lambda > 3` and `boundX` is strictly too small.

When `boundX < e^lambda`, `errorTerm` is smaller than the true tail-of-series bound. The algorithm may then prematurely declare a threshold `orders[i]` to be "certainly above `e^{-lambda}`" (the `cmp >= acc' + errorTerm` branch fires) even though the true exponential value has not yet been bounded tightly enough to confirm this. The result is that `expectedSeats` is set to `i` (or higher) when the correct answer is `0` (or lower), granting the voter seats they are not entitled to.

The code itself acknowledges the uncertainty with an open TODO:

> `-- TODO(peras): evaluate whether the limit used below (3) makes sense in this context.`
> `-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234`

---

### Impact Explanation

`localSortitionNumSeats` is the sole local-sortition eligibility gate in both `implVerifyVote` (line 376) and `implVerifyCert` (line 529) in `WFALS.hs`. Both paths accept a non-persistent voter's vote or certificate if and only if `nonZero numSeats` is `Just`:

```haskell
case nonZero numSeats of
  Nothing -> Left (ZeroNonPersistentSeats seatIndex)
  Just nonZeroNumSeats ->
    pure $ WFALSNonPersistentMember seatIndex voterStake vrfOutput nonZeroNumSeats
```

A false-positive seat count (caused by the incorrect `boundX`) makes this check pass for a voter whose VRF output should have yielded zero seats. The voter's vote is then accepted and counted toward the election result, and their certificate is accepted as valid. This is a bypass of the local-sortition eligibility check — the cryptographic VRF proof is valid, but the seat-count arithmetic is wrong, so the node accepts a vote that the protocol should reject.

The vote weight for non-persistent members is `numSeats * stake / totalNonPersistentStake`, so an inflated seat count also inflates the voter's effective voting power beyond what the protocol allows.

**Impact class**: High — bypass of local-sortition certificate/vote verification that enables unauthorized vote or certificate acceptance.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is easily reached in realistic committee configurations. For example, with `numNonPersistentVoters = 100` and a voter holding 2% of the non-persistent stake, `lambda = 2.0`. The error is not a corner case; it is the normal operating regime for any committee of meaningful size. An adversary who controls a pool with sufficient stake to push `lambda` above `ln(3)` can craft a VRF output that sits in the region where the underestimated error term causes a false-positive seat decision. Because the VRF output is attacker-controlled (the adversary signs with their own key), they can search for an output that triggers the incorrect branch.

---

### Recommendation

Replace the hardcoded `3` with the correct value `e^lambda`, computed using the same `FixedPoint` arithmetic already in scope:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

If a dependency on `exp` is undesirable, use a conservative upper bound that is provably ≥ `e^lambda` for all reachable values of `lambda`, and document the proof. The referenced upstream issue (https://github.com/tweag/cardano-peras/issues/234) should be resolved before this code is used in production.

---

### Proof of Concept

Consider:
- `numNonPersistentVoters = 10`
- `voterStake / totalNonPersistentStake = 0.5`
- `lambda = 5.0` → `e^lambda ≈ 148.4`, but `boundX = 3`

At `n = 2` Taylor terms, `acc' = 1 + (-5) + 12.5 = 8.5`, `err' = (-5)^3 / 6 ≈ -20.83`.

With the correct bound: `errorTerm = 20.83 * 148.4 ≈ 3091` — the algorithm correctly recognizes it has not converged and continues iterating.

With `boundX = 3`: `errorTerm = 20.83 * 3 ≈ 62.5` — the algorithm may prematurely fire the `cmp >= acc' + errorTerm` branch for a threshold `orders[0]` that is, say, `70`, concluding the voter is eligible for seat 0 when the true `e^{-5} ≈ 0.0067` is far below `orders[0]`.

The attacker entry path is a crafted `WFALSNonPersistentVote` message sent to any honest node running `implVerifyVote`. The VRF proof is valid (the attacker signs with their own key); only the seat-count arithmetic is wrong. The node accepts the vote and counts it toward the election result. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-125)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
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
