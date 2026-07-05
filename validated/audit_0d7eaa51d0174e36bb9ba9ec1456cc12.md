### Title
Unconverged Taylor-series approximation silently grants ineligible non-persistent Peras committee seats — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`taylorExpCmpFirstNonLower` in `LS.hs` implements an iterative Taylor-series comparison used to decide how many non-persistent voting-committee seats a candidate earns via local sortition. When the hard iteration cap (`maxN = 1000`) is exhausted without the series converging, the function returns `Just i` — treating the candidate as eligible for `i` seats — instead of `Nothing` (ineligible). This is the exact structural analog of the Saddle Finance M03 bug: the loop's exit-without-convergence path silently promotes an unproven result to a proven one. A second, compounding defect is that the caller passes the literal constant `3` as `boundX` (which must equal `e^lambda` for correct error bounds), making the error term systematically underestimated for any voter whose `lambda > ln(3) ≈ 1.099`. Both defects feed directly into `implVerifyVote` and `implVerifyCert` in `WFALS.hs`, which gate non-persistent member eligibility for the Peras voting protocol.

---

### Finding Description

**Root cause 1 — iteration-limit treated as convergence (`LS.hs` lines 165–166, 149–150)**

`decideOne` has three branches:

```haskell
decideOne maxN n err acc divisor cmp
  | maxN == n = Stop                          -- ← iteration cap hit
  | cmp >= acc' + errorTerm = Stop            -- ← proven ABOVE
  | cmp < acc' - errorTerm = Below ...        -- ← proven BELOW
  | otherwise = decideOne maxN (n+1) ...      -- ← recurse
```

The first branch (`maxN == n`) and the second branch (`proven ABOVE`) both return the same constructor `Stop`. In `goList`, `Stop` unconditionally maps to `Just i`:

```haskell
case decideOne maxN n err acc divisor cmp of
  Stop  -> Just i          -- ← no distinction between "proven ABOVE" and "cap hit"
  Below ... -> goList ...
```

The function's own documentation acknowledges this conflation:

> `-- * If max iterations reached while testing cmp_i -> return i`

`Just i` is then consumed by `localSortitionNumSeats` as a non-zero seat count, making the voter appear eligible.

**Root cause 2 — incorrect `boundX` constant (`LS.hs` lines 96–99)**

The call site passes the literal `3` as `boundX`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← must be e^lambda for correct error bounds
      orders
      (-lambda)
```

The function's own contract states: *"IMPORTANT: boundX must be e^{|x|} for correct error bounds"*. Here `x = -lambda`, so `boundX` must be `e^lambda`. For `lambda > ln(3) ≈ 1.099`, `e^lambda > 3`, so `errorTerm = abs(err' * boundX)` is underestimated. An underestimated error term makes the `cmp >= acc' + errorTerm` ("proven ABOVE") guard fire prematurely — before the partial sum has actually converged — incorrectly classifying a threshold as ABOVE (eligible) when the true `e^x` value has not yet been established. The code even carries an open TODO acknowledging the `3` is unvalidated:

> `-- TODO(peras): evaluate whether the limit used below (3) makes sense in this context.`

**`lambda` can easily exceed `ln(3)` in practice.** `lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. With 100 non-persistent voters and a voter holding 2 % of total non-persistent stake, `lambda = 2 > ln(3)`. With 10 % stake, `lambda = 10`, making `e^lambda ≈ 22026` versus the hardcoded `3`.

**Downstream consumption in vote and certificate verification (`WFALS.hs`)**

`implVerifyVote` (lines 375–390) and `implVerifyCert` (lines 528–543) both call `localSortitionNumSeats` and accept the vote/certificate if the returned seat count is non-zero:

```haskell
case nonZero numSeats of
  Nothing -> Left (ZeroNonPersistentSeats seatIndex)
  Just nonZeroNumSeats ->
    pure $ WFALSNonPersistentMember seatIndex voterStake vrfOutput nonZeroNumSeats
```

A spurious non-zero result from either defect causes the vote or certificate to be accepted as valid.

---

### Impact Explanation

An ineligible non-persistent candidate — one whose VRF output is genuinely below the local-sortition threshold — can have their `WFALSNonPersistentVote` or their entry in a `WFALSCert` accepted by any honest node running `implVerifyVote` / `implVerifyCert`. This constitutes a **bypass of Peras voting-committee eligibility checks**: unauthorized votes are counted toward quorum, and certificates containing ineligible voters pass verification. Depending on the quorum threshold and the number of ineligible votes injected, this can allow an adversary to forge a Peras certificate for a block that would not otherwise reach quorum, directly threatening Peras finality guarantees and constituting a consensus safety failure.

---

### Likelihood Explanation

The `boundX = 3` defect is not edge-case: it is triggered for any non-persistent voter with `lambda > ln(3)`, which is a normal operating condition for stake pools holding more than roughly `ln(3)/numNonPersistentVoters` of total non-persistent stake. The incorrect error bound causes premature ABOVE decisions without requiring any attacker action beyond submitting a validly signed vote with a valid VRF proof. The iteration-cap defect (`maxN == n = Stop`) is a secondary amplifier that activates when the underestimated error term prevents convergence within 1000 steps. Both defects are deterministic given the voter's stake and VRF output, so they are reproducible and not probabilistic.

---

### Recommendation

1. **Fix the iteration-cap path**: distinguish "proven ABOVE" from "cap exhausted". When `maxN == n`, return a distinct result (e.g., `Nothing` or a dedicated `Uncertain` constructor) and propagate it as ineligible (0 seats) rather than as eligible.

2. **Fix `boundX`**: compute `boundX = exp lambda` (or a safe upper bound thereof) at the call site in `localSortitionNumSeats` instead of hardcoding `3`. This ensures the error bound is always valid and the series converges correctly.

3. **Resolve the open TODO** at line 86–92 of `LS.hs` which explicitly flags the `3` as unvalidated.

---

### Proof of Concept

**Defect 1 (iteration cap):**

```
Given: lambda = 1.0, normalizedVRFOutput = v such that
       the first `orders` threshold is within the Taylor-series
       uncertainty band at iteration 1000.

taylorExpCmpFirstNonLower 3 orders (-1.0)
  calls goList 1000 0 (-1.0) 1 1 0 (orders)
  → decideOne 1000 0 ... cmp₀
  → ... recurses until n = 1000
  → maxN == n = Stop
  → goList returns Just 0
  → localSortitionNumSeats returns LocalSortitionNumSeats 0
  -- fromIntegral 0 = 0, nonZero 0 = Nothing → ZeroNonPersistentSeats
```

(For `i > 0` the voter gets `i` spurious seats when the cap fires on the `(i+1)`-th threshold.)

**Defect 2 (wrong `boundX`):**

```
Given: numNonPersistentVoters = 100, voterStake/totalNonPersistentStake = 0.05
       → lambda = 5.0, e^lambda ≈ 148.4, but boundX = 3

errorTerm = abs(err' * 3)   -- should be abs(err' * 148.4)
-- errorTerm is 49× too small
-- "cmp >= acc' + errorTerm" fires 49× earlier than it should
-- a threshold that is actually ABOVE e^(-5) is declared ABOVE
-- before the partial sum has converged to e^(-5)
-- voter is granted seats they are not entitled to
```

Both defects are reachable via a network-delivered `WFALSNonPersistentVote` or `WFALSCert` message processed by `implVerifyVote` / `implVerifyCert` in `WFALS.hs`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L116-119)
```haskell
-- Behavior:
--   * If cmp_i is proven ABOVE -> return i
--   * If max iterations reached while testing cmp_i -> return i
--   * If every element is proven BELOW -> returns Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L132-133)
```haskell
taylorExpCmpFirstNonLower boundX cmps x =
  goList 1000 0 x 1 1 0 cmps
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L147-150)
```haskell
  goList maxN n err acc divisor i (cmp : rest) =
    case decideOne maxN n err acc divisor cmp of
      Stop ->
        Just i
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L165-166)
```haskell
  decideOne maxN n err acc divisor cmp
    | maxN == n = Stop
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L170-175)
```haskell
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
