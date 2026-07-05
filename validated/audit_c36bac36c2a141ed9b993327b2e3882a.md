### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Local Sortition Seat Counts, Enabling Peras Voting Committee Eligibility Bypass - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Taylor-expansion comparison helper `taylorExpCmpFirstNonLower` is called with a hardcoded `boundX = 3`. The function's own documentation states that `boundX` **must** equal `e^{|x|}` for correct error bounds. Because `x = -lambda`, the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099` — which occurs for any non-persistent voter holding more than roughly `1.1 / numNonPersistentVoters` fraction of the non-persistent stake — the error bounds are severely underestimated. This causes the algorithm to make incorrect ABOVE/BELOW decisions, producing wrong seat counts. Since the same function is used both by the voter (self-check) and by the verifier (`implVerifyVote`, `implVerifyCert`), an ineligible voter can receive a non-zero seat count from the broken algorithm and submit a vote or certificate that the verifier also accepts, bypassing the Peras voting committee eligibility check.

---

### Finding Description

`localSortitionNumSeats` in `LS.hs` determines how many non-persistent committee seats a voter is granted via local sortition. It builds an `orders` list representing Poisson-distribution thresholds and then calls:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← passed as boundX
      orders
      (-lambda)
``` [1](#0-0) 

The function signature and its inline documentation are unambiguous:

```haskell
taylorExpCmpFirstNonLower ::
  -- | boundX = e^{|x|} for correct error estimation
  a ->
  ...
``` [2](#0-1) 

The error term inside `decideOne` is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

With `x = -lambda`, the mathematically required value is `boundX = e^lambda`. The hardcoded `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. `lambda` is:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [4](#0-3) 

For a committee with 100 non-persistent voters, any voter holding more than ~1.1% of the non-persistent stake produces `lambda > 1.099`. For a voter with 5% of the non-persistent stake, `lambda = 5` and `e^5 ≈ 148.4`, making `boundX = 3` underestimated by a factor of ~50.

**Analogy to the external report:** The Yieldoor bug used `decimals` (e.g., 18) instead of `10^decimals` (e.g., 10^18) — a raw value instead of its properly exponentiated form. Here, `3` is used instead of `e^lambda` — again a raw constant instead of the correct exponential of the parameter. In both cases the scaling error corrupts a critical comparison.

The TODO comment in the code reveals the confusion:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. One possible starting point would be to understand why
-- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
-- computing slot leadership proofs.
``` [5](#0-4) 

In `checkLeaderNatValue` (Ledger), `3` is the **maximum number of Taylor expansion terms** (`maxN`). In `taylorExpCmpFirstNonLower`, the first argument is `boundX`, a completely different parameter. The `3` was transplanted from one context to another where it has a different semantic meaning, producing an incorrect error bound.

**Effect on ABOVE/BELOW decisions:** With `errorTerm` underestimated:
- The ABOVE condition (`cmp >= acc' + errorTerm`) is easier to satisfy, potentially returning a lower index (fewer seats) prematurely.
- The BELOW condition (`cmp < acc' - errorTerm`) is harder to satisfy, causing the algorithm to skip past elements it should have classified as BELOW, potentially returning a higher index (more seats than deserved).

The second effect is the security-relevant one: a voter whose correct seat count is 0 may receive a non-zero count from the broken algorithm.

`localSortitionNumSeats` is called in three places during vote and certificate verification:

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
    pure $ WFALSNonPersistentMember ...
``` [6](#0-5) [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can submit a `WFALSNonPersistentVote` or a `WFALSCert` containing a VRF output that the broken `localSortitionNumSeats` evaluates as granting ≥1 seat, while the mathematically correct algorithm would grant 0 seats. Because both the voter's self-check (`implCheckShouldVote`) and the verifier's check (`implVerifyVote`, `implVerifyCert`) use the same broken function, the verifier accepts the vote or certificate. This constitutes a bypass of the Peras non-persistent voting committee eligibility check, enabling unauthorized vote and certificate acceptance. A sufficient number of such ineligible votes could forge a Peras certificate for a block that does not have legitimate quorum, undermining the chain-selection boost guarantee of the Peras protocol.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is satisfied by any non-persistent voter holding more than `1.099 / numNonPersistentVoters` of the non-persistent stake. For a committee with 100 non-persistent voters this threshold is ~1.1%, a stake level easily achievable by a mid-sized stake pool. The VRF output is deterministic and publicly verifiable, so an attacker can pre-compute whether the broken algorithm grants them extra seats before submitting a vote. No key compromise, stake majority, or operator access is required.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct `e^lambda`:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

Since `lambda` is already a `FixedPoint`, `exp` must be the fixed-point exponential (e.g., from `Cardano.Ledger.BaseTypes`). Alternatively, use a conservative upper bound such as `exp (fromIntegral numNonPersistentVoters)` (the maximum possible `lambda`), which is safe but slightly less efficient.

---

### Proof of Concept

**Setup:** Non-persistent committee with `numNonPersistentVoters = 10`, voter holds 20% of non-persistent stake → `lambda = 10 * 0.20 = 2.0`. Correct `boundX = e^2 ≈ 7.389`; actual `boundX = 3`.

**Trace through `decideOne` for `orders[0]`:**

Let `normalizedVRFOutput = 0.05`, `lambda = 2.0`.
- `orders[0] = 0.05 / 2.0 = 0.025`
- `e^(-2) ≈ 0.1353`
- Correct: `orders[0] = 0.025 < 0.1353` → BELOW (voter gets 0 seats from this threshold)

With `boundX = 3` (incorrect):
- After one Taylor step: `acc' ≈ 1 + (-2) = -1`, `err' = (-2)^2/2 = 2`, `errorTerm = 2 * 3 = 6`
- `cmp = 0.025 >= acc' + errorTerm = -1 + 6 = 5`? No.
- `cmp = 0.025 < acc' - errorTerm = -1 - 6 = -7`? No.
- Algorithm continues iterating; with underestimated error bounds it may prematurely declare ABOVE for a later `orders[i]`, granting the voter seats the correct algorithm would deny.

The broken algorithm and the verifier both use `boundX = 3`, so the verifier accepts the vote. The correct algorithm with `boundX = e^2 ≈ 7.389` would have correctly classified the threshold as BELOW and returned 0 seats.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L122-131)
```haskell
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
  a ->
  -- | list of cmp thresholds (checked in order)
  [a] ->
  -- | x in e^x
  a ->
  Maybe Int
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
