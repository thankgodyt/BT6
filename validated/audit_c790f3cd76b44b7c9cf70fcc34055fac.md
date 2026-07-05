### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Peras Non-Persistent Seat Counts for Voters with Large Stake — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Taylor-series comparison helper `taylorExpCmpFirstNonLower` is called with a hardcoded `boundX = 3`. The function's own precondition states that `boundX` **must equal `e^|x|`** for the error bound to be correct. Because `x = -lambda` and `lambda` is the voter's Poisson parameter, the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099` — a routine condition for any non-persistent voter holding more than roughly `1.1 / numNonPersistentVoters` of the non-persistent stake pool — the supplied constant underestimates the true error bound, causing the algorithm to terminate early with an incorrect seat count. The code itself flags this with an open TODO acknowledging the value may be wrong.

---

### Finding Description

`localSortitionNumSeats` computes the Poisson parameter `lambda` as:

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [1](#0-0) 

It then calls:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- <-- hardcoded boundX
      orders
      (-lambda)
``` [2](#0-1) 

The function's own documentation states:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [3](#0-2) 

Inside `decideOne`, the error term is computed as:

```haskell
errorTerm = abs (err' * boundX)
``` [4](#0-3) 

When `boundX < e^lambda` (i.e., `lambda > ln(3) ≈ 1.099`), `errorTerm` is smaller than the true Taylor remainder. The two early-exit conditions:

```haskell
| cmp >= acc' + errorTerm = Stop   -- "definitely ABOVE"
| cmp < acc' - errorTerm  = Below  -- "definitely BELOW"
``` [5](#0-4) 

…fire with an artificially narrow uncertainty band. A threshold `orders[i]` that is genuinely ambiguous (within the true error margin) is incorrectly classified as ABOVE or BELOW, yielding a wrong seat index. The code's own TODO confirms this is unresolved:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [6](#0-5) 

The computed `numSeats` is then used directly in vote verification:

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
``` [7](#0-6) 

The same call appears in `implVerifyCert`: [8](#0-7) 

And in `implCheckShouldVote`: [9](#0-8) 

The vote weight for non-persistent members is then derived directly from `numSeats`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [10](#0-9) 

---

### Impact Explanation

The incorrect seat count propagates into two security-critical paths:

1. **Vote acceptance with inflated weight**: If `orders[i]` is misclassified as ABOVE when it is actually BELOW, the voter is granted seat index `i` instead of a lower value. Their `VoteWeight` is proportionally inflated. A verifying node accepts this vote and its associated weight without detecting the discrepancy, because both the voter and the verifier run the same buggy `localSortitionNumSeats`. This constitutes unauthorized vote acceptance — a bypass of Peras voting checks.

2. **Certificate verification inconsistency**: `implVerifyCert` recomputes `numSeats` independently. If the error causes a different rounding outcome on different nodes (e.g., due to `FixedPoint` representation differences at the boundary), a certificate that one node accepts another may reject, breaking cross-node consensus on Peras certificate validity.

This matches the allowed impact: **Bypass of Peras voting or certificate checks enabling unauthorized vote acceptance**, and **chain-selection/security-threshold weakening** if the effective committee composition diverges from the protocol's security assumptions.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is reached whenever:

```
numNonPersistentVoters × (voterStake / totalNonPersistentStake) > 1.099
```

With a committee of 100 non-persistent seats, any voter holding more than ~1.1% of non-persistent stake triggers the bug. With 1000 seats, the threshold is ~0.11%. Both are realistic stake concentrations on a live network. No special privileges, key compromise, or majority stake are required — any legitimate non-persistent voter candidate with moderate stake is sufficient.

---

### Recommendation

Replace the hardcoded `3` with the dynamically computed `e^lambda`. Since `lambda` is already available as a `FixedPoint`, compute `boundX = exp lambda` (or a safe upper bound derived from `lambda`) before calling `taylorExpCmpFirstNonLower`:

```haskell
-- boundX must be e^lambda for correct error bounds
let boundX = exp lambda  -- or a conservative ceiling
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      boundX
      orders
      (-lambda)
```

This mirrors the fix recommended in the external report: replace the hardcoded precision constant with a value derived from the actual runtime parameter. The open issue at https://github.com/tweag/cardano-peras/issues/234 should be resolved before the Peras protocol is activated on mainnet.

---

### Proof of Concept

**Setup**: A private testnet running the Peras protocol with the following parameters:
- `numNonPersistentVoters = 100`
- A voter holding 5% of non-persistent stake → `lambda = 5.0`
- `e^5 ≈ 148.4`, but `boundX = 3`

**Trigger**:
1. The voter computes their VRF output for an election.
2. `localSortitionNumSeats` is called with `lambda = 5.0`.
3. `taylorExpCmpFirstNonLower 3 orders (-5.0)` is invoked.
4. `errorTerm = abs(err' * 3)` instead of `abs(err' * 148.4)` — underestimated by ~50×.
5. An `orders[i]` value within the true error margin of `e^(-5) ≈ 0.00674` is misclassified.
6. The voter receives seat count `i` (e.g., 6) instead of the correct value (e.g., 5).
7. `implVerifyVote` accepts the vote with `VoteWeight = 6 × stake / totalNonPersistentStake` instead of `5 × stake / totalNonPersistentStake`.
8. The inflated vote weight is accepted into a Peras certificate, granting the voter ~20% more voting power than the protocol intends.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-301)
```haskell
          let numSeats =
                localSortitionNumSeats
                  (nonPersistentCommitteeSize committee)
                  (totalNonPersistentStake committee)
                  ourStake
                  (normalizeVRFOutput vrfOutput)
          case nonZero numSeats of
            Nothing ->
              pure Nothing
            Just nonZeroNumSeats ->
              pure $
                Just $
                  WFALSNonPersistentMember
                    seatIndex
                    ourStake
                    vrfOutput
                    nonZeroNumSeats
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
