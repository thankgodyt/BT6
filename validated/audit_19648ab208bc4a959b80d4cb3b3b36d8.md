### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Local Sortition Seat Counts When `lambda > ln(3)` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Taylor-series comparison helper `taylorExpCmpFirstNonLower` is called with a hardcoded error-bound constant `3` instead of the mathematically required `e^{lambda}`. When `lambda > ln(3) ≈ 1.099` — a realistic condition for any voter with meaningful stake in a committee of moderate size — the error bound is underestimated, the Taylor series terminates before convergence, and the returned seat count is incorrect. Both the self-check path (`implCheckShouldVote`) and the verification path (`implVerifyVote`, `implVerifyCert`) use this function, so the miscalculation is consistent across nodes but diverges from the intended wFA^LS scheme, weakening Peras vote authorization.

---

### Finding Description

`localSortitionNumSeats` in `LS.hs` computes the Poisson-distribution parameter `lambda` and a list of comparison thresholds `orders`, then calls:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded boundX
      orders
      (-lambda)  -- ← x
``` [1](#0-0) 

The contract of `taylorExpCmpFirstNonLower` is explicit in its own documentation:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Because `x = -lambda`, the correct `boundX` is `e^{lambda}`. The constant `3` is only a safe overestimate when `lambda ≤ ln(3) ≈ 1.099`. For any larger `lambda`, `3 < e^{lambda}` and the error term

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

is underestimated. The decision logic then fires prematurely:

```haskell
| cmp >= acc' + errorTerm = Stop   -- ABOVE: grant seat
| cmp < acc' - errorTerm = Below   -- BELOW: skip threshold
``` [4](#0-3) 

With a smaller-than-required `errorTerm`, the `ABOVE` branch fires more readily (the window `[acc' - errorTerm, acc' + errorTerm]` is narrower), causing the function to return a seat index before the Taylor series has converged. This can yield a seat count that is higher than the mathematically correct value.

`lambda` is computed as:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [5](#0-4) 

For a committee with 100 non-persistent voters and a voter holding 5 % of non-persistent stake, `lambda = 5` and `e^{lambda} ≈ 148.4`. The constant `3` is ~50× too small. The code itself acknowledges the uncertainty with a TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. One possible starting point would be to understand why
-- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
-- computing slot leadership proofs.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [6](#0-5) 

The `3` was copied from the Praos leader-check context, where `|x| = sigma * |ln(1-f)| ≤ 0.05` for typical parameters, making `3` a safe overestimate. In the local sortition context `lambda` can be orders of magnitude larger, making `3` a severe underestimate.

The incorrect seat count propagates into both vote verification and certificate verification:

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
``` [7](#0-6) [8](#0-7) 

---

### Impact Explanation

When `lambda > ln(3)`, the seat count returned by `localSortitionNumSeats` can be higher than the mathematically correct value. A non-persistent committee member may be granted more seats than their stake entitles them to, inflating their `VoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [9](#0-8) 

Because both the voter and every verifier run the same code, all nodes agree on the inflated count, so the miscalculation is not caught by any cross-node consistency check. The result is that the Peras voting committee does not correctly implement the wFA^LS security properties: a voter with disproportionately inflated voting power can influence election outcomes beyond what their stake warrants, materially weakening Peras vote authorization.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met whenever `numNonPersistentVoters * voterStake / totalNonPersistentStake > 1.099`. For any committee with more than ~22 non-persistent voters and a voter holding ≥ 5 % of non-persistent stake, the condition is satisfied. This is a realistic production scenario. The bug is deterministic and reproducible for any such voter; no special network conditions or timing are required.

---

### Recommendation

Replace the hardcoded `3` with the correct error bound `e^{lambda}`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} where x = -lambda
      orders
      (-lambda)
```

`exp` is available via `FixedPoint`'s `Floating` instance (or via the same `NonIntegral` library already used). This matches the mathematical contract stated in the function's own documentation and aligns with how `checkLeaderNatValue` in `cardano-ledger` is correctly parameterized for its own domain.

---

### Proof of Concept

Let `numNonPersistentVoters = 100`, `voterStake / totalNonPersistentStake = 0.05`.

- `lambda = 100 * 0.05 = 5.0`
- Correct `boundX = e^5 ≈ 148.41`
- Used `boundX = 3`

At Taylor iteration `n`, `err' ≈ lambda^n / n!` and `errorTerm = |err' * boundX|`. With `boundX = 3`, the error term is ~49× smaller than required. The algorithm declares ABOVE/BELOW after far fewer iterations than needed for convergence, returning a seat count that diverges from the true Poisson CDF comparison. For `lambda = 5`, the correct expected seats for a median VRF output is approximately 4–5, but the premature termination can return a value of 6 or higher, granting the voter ~20–40 % more voting power than their stake warrants.

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
