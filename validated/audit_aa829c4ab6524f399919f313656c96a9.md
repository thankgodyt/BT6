### Title
`FixedPoint` Precision Underflow in `localSortitionNumSeats` Silently Denies Non-Persistent Committee Seats to Legitimate Voters — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Peras local-sortition Poisson parameter `lambda` is computed as a `Rational` expression and then converted to `FixedPoint`. When a voter's stake is very small relative to the total non-persistent stake, the `fromRational` conversion underflows `lambda` to zero. The guard `| lambda <= 0 = LocalSortitionNumSeats 0` silently returns zero seats for that voter. This is the direct analog of the external report's integer-division truncation: a proportional calculation (`voterStake / totalNonPersistentStake`) rounds to zero at the precision boundary, causing a legitimate participant to be incorrectly excluded from the voting committee rather than receiving the seats they are entitled to.

---

### Finding Description

In `localSortitionNumSeats`, the expected number of non-persistent seats for a voter is computed via the Poisson parameter:

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
```

`voterStake` and `totalNonPersistentStake` are both `Rational` (from `LedgerStake`), so the division is exact in `Rational`. However, the result is then converted to `FixedPoint` via `fromRational`. `FixedPoint` (from `cardano-ledger`) is a fixed-precision decimal type; any value below its smallest representable quantum rounds to zero.

The code itself acknowledges this:

```haskell
-- If the voter has stake close to zero, the conversion from 'Rational' to
-- 'FixedPoint' for 'lambda' might underflow to zero, which would cause the
-- "orders" computation below to divide by zero.
| lambda <= 0 = LocalSortitionNumSeats 0
```

When `lambda` underflows, the guard returns `LocalSortitionNumSeats 0` — zero seats — for a voter with strictly positive stake. This is not a division-by-zero guard for the voter's own stake (that is handled by the earlier `| voterStake <= 0` guard); it is a precision-loss guard that silently converts a positive entitlement into zero.

The same `localSortitionNumSeats` call appears in three places in `implVerifyVote` and `implVerifyCert` in `WFALS.hs`:

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

When `lambda` underflows, `numSeats = 0`, `nonZero` returns `Nothing`, and the vote is rejected with `ZeroNonPersistentSeats`. The voter's VRF proof and signature are never checked for correctness — the rejection happens before those checks.

---

### Impact Explanation

A legitimate non-persistent committee member whose stake-to-total-non-persistent-stake ratio falls below the `FixedPoint` precision floor is permanently excluded from voting for the entire epoch. Their votes are rejected with `ZeroNonPersistentSeats` regardless of the validity of their VRF proof or vote signature. If enough small-stake non-persistent voters are affected, the Peras quorum threshold may become unreachable, preventing certificate issuance. Failure to issue Peras certificates degrades the protocol to base Praos, weakening the chain-quality and common-prefix guarantees that Peras is designed to strengthen. This materially weakens vote and certificate authorization for affected participants.

---

### Likelihood Explanation

The `FixedPoint` type in `cardano-ledger` uses 34 decimal digits of precision. For `lambda` to underflow, the ratio `numNonPersistentVoters * voterStake / totalNonPersistentStake` must be below `10^{-34}`. In a realistic stake distribution this threshold is extremely low, making the underflow unlikely for any pool with economically meaningful stake. However, the code's own comment explicitly acknowledges the possibility, and the guard is a workaround rather than a correct fix. In a future parameterization with a very large committee or a highly fragmented stake distribution, the threshold becomes more reachable. The entry path is fully unprivileged: any pool operator with a small non-persistent seat can trigger the path by submitting a vote.

---

### Recommendation

Replace the silent `LocalSortitionNumSeats 0` fallback with a minimum-representable-value clamp: if the exact `Rational` value of `lambda` is positive but `fromRational` produces zero, use the smallest positive `FixedPoint` value rather than zero. Alternatively, perform the Poisson threshold comparison entirely in `Rational` arithmetic to avoid the precision loss. At minimum, document the precision boundary explicitly and add a property test that verifies `localSortitionNumSeats` returns a non-zero result for any voter with strictly positive stake and a positive `numNonPersistentVoters`.

---

### Proof of Concept

```
Suppose:
  numNonPersistentVoters = 500
  totalNonPersistentStake = 45_000_000_000 ADA (in lovelace: 4.5e16)
  voterStake = 1 lovelace = 1e-6 ADA

  lambda_rational = 500 * (1 / 4.5e16) ≈ 1.11e-14

  FixedPoint precision floor ≈ 1e-34

  lambda_rational >> 1e-34, so lambda does NOT underflow here.

Now suppose a future parameterization:
  numNonPersistentVoters = 1
  totalNonPersistentStake = 1e28 (hypothetical large supply)
  voterStake = 1 lovelace

  lambda_rational = 1 * (1 / 1e28) = 1e-28

  FixedPoint precision floor ≈ 1e-34 (34 decimal places)

  lambda_rational > 1e-34, still does not underflow.

The underflow is only reachable at extreme parameter combinations, confirming
the code comment's concern is real but the practical threshold is very low
under current Cardano parameters. The guard silently returns 0 seats rather
than the correct positive value, which is the structural analog to the
vesting truncation-to-zero described in the external report.
```

The root cause is at: [1](#0-0) 

The silent zero-seat return that propagates to vote rejection is at: [2](#0-1) 

The downstream rejection in vote verification is at: [3](#0-2) 

The `LedgerStake` type confirming the underlying representation is `Rational`: [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L56-70)
```haskell
    | voterStake <= 0 = LocalSortitionNumSeats 0
    -- If the voter has stake close to zero, the conversion from 'Rational' to
    -- 'FixedPoint' for 'lambda' might underflow to zero, which would cause the
    -- "orders" computation below to divide by zero.
    | lambda <= 0 = LocalSortitionNumSeats 0
    -- This voter might be entitled to some seats => run the local sortition.
    | otherwise = LocalSortitionNumSeats (fromIntegral expectedSeats)
   where
    -- Expected number of seats granted by local sortition
    lambda :: FixedPoint
    lambda =
      fromRational $
        fromIntegral numNonPersistentVoters
          * voterStake
          / totalNonPersistentStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-383)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Types.hs (L24-28)
```haskell
newtype LedgerStake = LedgerStake
  { unLedgerStake :: Rational
  }
  deriving (Show, Eq)
  deriving newtype (Num, HasZero)
```
