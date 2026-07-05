### Title
`FixedPoint` Precision Underflow in `localSortitionNumSeats` Silently Excludes Legitimate Non-Persistent Peras Committee Members — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Poisson parameter `lambda` (expected number of seats for a non-persistent voter) is computed as a `FixedPoint` value. When a voter's stake fraction is sufficiently small, the `Rational`-to-`FixedPoint` conversion underflows to zero. A guard then silently returns `LocalSortitionNumSeats 0`, causing every vote and certificate from that voter to be rejected with `ZeroNonPersistentSeats`. This is the direct structural analog of the BetaFinance interest-accrual precision loss: a small-magnitude value rounds to zero, silently corrupting a security-critical calculation. A compounding issue — a hardcoded `boundX = 3` that should be `e^lambda` — further corrupts the seat-count result for voters with `lambda > ln(3)`.

---

### Finding Description

**Root cause — `lambda` underflow to zero:**

In `localSortitionNumSeats`, `lambda` is the expected number of non-persistent seats for a voter:

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [1](#0-0) 

`FixedPoint` (from `cardano-ledger`) has limited fixed-point precision (~34 decimal bits, minimum representable value ≈ `10^{-10}`). When `numNonPersistentVoters * voterStake / totalNonPersistentStake` falls below this minimum, `fromRational` truncates to zero.

The code itself acknowledges this:

```haskell
-- If the voter has stake close to zero, the conversion from 'Rational' to
-- 'FixedPoint' for 'lambda' might underflow to zero, which would cause the
-- "orders" computation below to divide by zero.
| lambda <= 0 = LocalSortitionNumSeats 0
``` [2](#0-1) 

When `lambda = 0`, the function returns `LocalSortitionNumSeats 0`. In both `implVerifyVote` and `implVerifyCert`, the call to `nonZero numSeats` then returns `Nothing`, and the vote or certificate is rejected:

```haskell
case nonZero numSeats of
  Nothing ->
    Left (ZeroNonPersistentSeats seatIndex)
``` [3](#0-2) 

The same path is taken in `implVerifyCert`: [4](#0-3) 

**Compounding issue — hardcoded `boundX = 3`:**

For voters whose `lambda` does not underflow, the seat count is computed via:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3        -- boundX = e^{|x|} for correct error estimation
      orders
      (-lambda)
``` [5](#0-4) 

The contract of `taylorExpCmpFirstNonLower` requires `boundX = e^{|x|}`. Here `x = -lambda`, so the correct value is `e^lambda`. The hardcoded `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. For any voter with `lambda > 1.099` (i.e., a voter holding more than `1.099 / numNonPersistentVoters` of the non-persistent stake), the error bound is underestimated, and the Taylor comparison may terminate early with an incorrect seat count. The code itself flags this as unresolved:

```haskell
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. ...
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [6](#0-5) 

The `decideOne` inner function uses `errorTerm = abs (err' * boundX)` to decide whether the Taylor partial sum has converged. With `boundX` too small, `errorTerm` is too small, causing the algorithm to declare convergence prematurely and return an incorrect index — i.e., an incorrect seat count. [7](#0-6) 

---

### Impact Explanation

**Quorum weakening via systematic exclusion.** `LedgerStake` is a `Rational` wrapper, so the underlying stake values are exact: [8](#0-7) 

The precision loss occurs only at the `Rational`-to-`FixedPoint` conversion boundary. Any non-persistent voter whose `lambda` underflows to zero is silently excluded: their votes are rejected with `ZeroNonPersistentSeats`, and `implCheckShouldVote` returns `Nothing` so they do not vote at all. [9](#0-8) 

The quorum check in `stakeAboveThreshold` compares accumulated `PerasVoteStake` against a fixed `perasQuorumStakeThreshold`: [10](#0-9) 

If the quorum threshold is parameterized assuming all eligible non-persistent voters can contribute stake, but a subset is silently excluded due to `FixedPoint` underflow, the maximum achievable non-persistent stake toward quorum is lower than the protocol designers assumed. A coalition that would otherwise fall short of quorum may now exceed it, enabling unauthorized certificate acceptance.

**Incorrect seat count via wrong `boundX`.** For voters with `lambda > ln(3)`, the incorrect error bound can cause `taylorExpCmpFirstNonLower` to return a seat count that is too high. A higher seat count inflates `VoteWeight` in `implEligiblePartyVoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [11](#0-10) 

An inflated `VoteWeight` allows a non-persistent voter to contribute more stake toward quorum than their ledger stake entitles them to, materially weakening certificate authorization.

---

### Likelihood Explanation

For a committee with `numNonPersistentVoters = 500` (a plausible Peras parameterization), a voter holding less than `2 × 10^{-13}` of the total non-persistent stake will have `lambda` underflow. Small stake pools that are just above the persistent-seat threshold are the most likely candidates. The `boundX` issue affects any voter with more than `1.099 / numNonPersistentVoters` of the non-persistent stake — for 500 voters, that is any voter with more than ~0.22% of non-persistent stake, which is a very common scenario. Both conditions are reachable by an unprivileged peer submitting a crafted vote or certificate over the standard Peras miniprotocol.

---

### Recommendation

1. **`lambda` underflow**: Perform the entire `lambda` computation and the `orders` list in `Rational` arithmetic. Convert to `FixedPoint` only at the final comparison step, or use a higher-precision type that can represent the required range without underflow.
2. **`boundX` constant**: Replace the hardcoded `3` with `exp lambda` (computed in `FixedPoint` or `Double`). This is the mathematically required value per the function's own contract comment. Track and resolve the linked issue https://github.com/tweag/cardano-peras/issues/234.
3. **Documentation**: Until fixed, document the minimum stake fraction below which a non-persistent voter will be silently excluded, and ensure the quorum threshold is set conservatively to account for this exclusion.

---

### Proof of Concept

**`lambda` underflow scenario:**

```
numNonPersistentVoters = 500
totalNonPersistentStake = 1  (normalized)
voterStake = 1.5e-13

lambda_rational = 500 * 1.5e-13 / 1 = 7.5e-11

FixedPoint minimum ≈ 1e-10

fromRational 7.5e-11 :: FixedPoint  →  0

Guard fires: | lambda <= 0 = LocalSortitionNumSeats 0

implVerifyVote: nonZero (LocalSortitionNumSeats 0) = Nothing
             → Left (ZeroNonPersistentSeats seatIndex)
```

The voter has positive ledger stake and a valid VRF proof, but their vote is rejected.

**`boundX` inflation scenario:**

```
numNonPersistentVoters = 10
voterStake / totalNonPersistentStake = 0.25

lambda = 10 * 0.25 = 2.5
e^lambda = e^2.5 ≈ 12.18

taylorExpCmpFirstNonLower 3 orders (-2.5)
  -- errorTerm = |err' * 3| instead of |err' * 12.18|
  -- error bound underestimated by factor ~4x
  -- algorithm may declare ABOVE prematurely
  -- returns seat count = 3 instead of correct 2

VoteWeight = 3 * voterStake / totalNonPersistentStake = 0.75
  -- correct value: 2 * 0.25 = 0.50
  -- inflated by 50%
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L57-60)
```haskell
    -- If the voter has stake close to zero, the conversion from 'Rational' to
    -- 'FixedPoint' for 'lambda' might underflow to zero, which would cause the
    -- "orders" computation below to divide by zero.
    | lambda <= 0 = LocalSortitionNumSeats 0
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L291-293)
```haskell
          case nonZero numSeats of
            Nothing ->
              pure Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L381-383)
```haskell
        case nonZero numSeats of
          Nothing ->
            Left (ZeroNonPersistentSeats seatIndex)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L534-536)
```haskell
              case nonZero numSeats of
                Nothing ->
                  Left (ZeroNonPersistentSeats seatIndex)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Types.hs (L24-28)
```haskell
newtype LedgerStake = LedgerStake
  { unLedgerStake :: Rational
  }
  deriving (Show, Eq)
  deriving newtype (Num, HasZero)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```
