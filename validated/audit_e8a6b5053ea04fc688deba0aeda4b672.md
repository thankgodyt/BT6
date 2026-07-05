### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Error Bounds for Non-Persistent Peras Committee Seat Counts When `lambda > ln(3)` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` determines how many non-persistent Peras voting-committee seats a pool is granted via a Poisson-distribution check. The check relies on `taylorExpCmpFirstNonLower`, which requires its first argument (`boundX`) to equal `e^{|x|}` for correct error bounds. The function is called with the hardcoded literal `3`, but `x = -lambda` and `e^lambda > 3` whenever `lambda > ln(3) ≈ 1.099`. Because `lambda = numNonPersistentVoters × voterStake / totalNonPersistentStake`, this threshold is crossed by any pool holding more than `ln(3) / numNonPersistentVoters` of the non-persistent stake — a fraction that is routinely exceeded in realistic committee configurations. The underestimated error bound causes the Taylor expansion to terminate with an incorrect decision, granting a pool more or fewer non-persistent seats than the Poisson distribution dictates.

---

### Finding Description

`localSortitionNumSeats` computes `lambda` as a `FixedPoint` value and then calls:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded boundX
      orders
      (-lambda)
``` [1](#0-0) 

The contract of `taylorExpCmpFirstNonLower` is stated in its own docstring:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Inside `decideOne`, the error term is computed as:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `boundX < e^lambda`, `errorTerm` is smaller than the true remainder of the Taylor series. The decision band `[acc' − errorTerm, acc' + errorTerm]` no longer reliably contains `e^{−lambda}`, so the function can:

- Return `Stop` (not certainly below) for a threshold that is actually below `e^{−lambda}` → voter is denied a seat they earned.
- Return `Below` (certainly below) for a threshold that is actually above `e^{−lambda}` → voter is granted a seat they did not earn.

The direction of the error depends on whether the partial sum `acc'` is an overestimate or underestimate at the iteration where the premature decision fires, which varies with `lambda` and `normalizedVRFOutput`.

`lambda` is computed from:

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [4](#0-3) 

`LedgerStake` wraps a `Rational`:

```haskell
newtype LedgerStake = LedgerStake
  { unLedgerStake :: Rational
  }
``` [5](#0-4) 

The division `voterStake / totalNonPersistentStake` is exact rational arithmetic; the precision loss occurs only at the `fromRational → FixedPoint` conversion and, critically, at the `boundX = 3` error-bound underestimation. For a committee with `numNonPersistentVoters = 100`, any pool holding more than `ln(3)/100 ≈ 1.1 %` of the non-persistent stake produces `lambda > ln(3)`. For `numNonPersistentVoters = 500`, the threshold drops to `≈ 0.22 %`. Both are routine in a live stake distribution.

The code itself acknowledges the problem with a TODO and a tracked issue:

```haskell
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. One possible starting point would be to understand why
-- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
-- computing slot leadership proofs.
--
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [6](#0-5) 

The reference to `checkLeaderNatValue` is misleading: in Praos, `|x| = |ln(1−f)| ≈ 0.051` for `f = 0.05`, so `e^{|x|} ≈ 1.052` and `3` is a safe over-approximation. For Peras local sortition, `lambda` scales with committee size and individual stake fraction, making `3` an under-approximation for any pool with non-trivial stake.

`localSortitionNumSeats` is called on both the voter side (`implCheckShouldVote`) and the verifier side (`implVerifyVote` and `implVerifyCert`): [7](#0-6) [8](#0-7) [9](#0-8) 

Because both sides execute the same deterministic function with the same inputs, they reach the same (incorrect) seat count. A pool that is incorrectly granted `k > 0` seats will have its vote accepted by every honest verifier, because every honest verifier replicates the same faulty computation.

---

### Impact Explanation

A non-persistent Peras committee member whose `lambda > ln(3)` can be granted more non-persistent seats than the Poisson distribution dictates. Because `implVerifyVote` and `implVerifyCert` reproduce the same computation, the inflated seat count is accepted by all honest nodes. The pool's `VoteWeight` in `implEligiblePartyVoteWeight` is proportional to `unNonZero numSeats`: [10](#0-9) 

An adversary who can arrange `lambda` to land just above a Poisson threshold at an even Taylor-expansion step (where `acc' > e^{−lambda}`) will have the threshold incorrectly classified as "certainly below", receiving an extra seat and proportionally more voting weight. This constitutes a bypass of the Peras voting committee seat-count check, allowing unauthorized vote weight to be accepted by honest nodes.

**Impact: High** — committee selection bug that lets a pool with `lambda > ln(3)` (a common condition) obtain more non-persistent Peras voting seats than the protocol intends, weakening the security threshold of the Peras finality gadget.

---

### Likelihood Explanation

The condition `lambda > ln(3)` is met by any pool holding more than `ln(3) / numNonPersistentVoters` of the non-persistent stake. For a 100-seat non-persistent committee this is 1.1 %; for a 500-seat committee it is 0.22 %. Any pool with meaningful stake in a live Cardano network will routinely exceed this threshold. No special privileges, key compromise, or majority stake are required — only participation as a registered stake pool.

---

### Recommendation

Replace the hardcoded `3` with the correct upper bound `e^lambda`, computed before calling `taylorExpCmpFirstNonLower`:

```haskell
-- boundX must be e^lambda for correct error bounds
let boundX = exp (toRational lambda)   -- or use a FixedPoint exp approximation
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (fromRational boundX)
      orders
      (-lambda)
```

Alternatively, adopt the same approach used by `checkLeaderNatValue` in `cardano-ledger`, which computes `e^{|c|}` analytically from the protocol parameter rather than hard-coding a constant. The tracked issue (https://github.com/tweag/cardano-peras/issues/234) should be resolved before Peras is activated on any production network.

---

### Proof of Concept

Let `numNonPersistentVoters = 100`, `voterStake / totalNonPersistentStake = 0.02` (2 % of non-persistent stake), giving `lambda = 2.0`. Then `e^lambda ≈ 7.389`, but `boundX = 3`.

At Taylor step `n = 2` (even), `acc' = 1 + (−2) + 2 = 1` (overestimate of `e^{−2} ≈ 0.135`). The true remainder bound is `|err'| × e^2 ≈ 0.667 × 7.389 ≈ 4.93`. The computed `errorTerm = |err'| × 3 ≈ 2.0`.

If `orders[0] = normalizedVRFOutput / lambda` evaluates to, say, `0.25`:
- True check: `0.25 ≥ acc' + 4.93 = 5.93`? No. `0.25 < acc' − 4.93 = −3.93`? No. → uncertain, continue.
- Faulty check: `0.25 ≥ acc' + 2.0 = 3.0`? No. `0.25 < acc' − 2.0 = −1.0`? No. → uncertain, continue.

At step `n = 3` (odd), `acc' ≈ 0.333` (underestimate). True remainder ≈ `0.667 × 7.389 ≈ 4.93`. Computed `errorTerm ≈ 0.667 × 3 = 2.0`.

- True check: `0.25 ≥ 0.333 + 4.93`? No. `0.25 < 0.333 − 4.93 = −4.6`? No. → uncertain.
- Faulty check: `0.25 ≥ 0.333 + 2.0 = 2.333`? No. `0.25 < 0.333 − 2.0 = −1.667`? No. → uncertain.

At step `n = 4` (even), `acc' ≈ 0.333 + 0.667/4 ≈ 0.5` (overestimate). True remainder ≈ `0.133 × 7.389 ≈ 0.985`. Computed `errorTerm ≈ 0.133 × 3 = 0.4`.

- True check: `0.25 ≥ 0.5 + 0.985 = 1.485`? No. `0.25 < 0.5 − 0.985 = −0.485`? No. → uncertain.
- Faulty check: `0.25 ≥ 0.5 + 0.4 = 0.9`? No. `0.25 < 0.5 − 0.4 = 0.1`? No. → uncertain.

At step `n = 5` (odd), `acc' ≈ 0.367` (underestimate). True remainder ≈ `0.027 × 7.389 ≈ 0.2`. Computed `errorTerm ≈ 0.027 × 3 = 0.081`.

- True check: `0.25 ≥ 0.367 + 0.2 = 0.567`? No. `0.25 < 0.367 − 0.2 = 0.167`? No. → uncertain.
- **Faulty check**: `0.25 ≥ 0.367 + 0.081 = 0.448`? No. `0.25 < 0.367 − 0.081 = 0.286`? **Yes** → `Below` (certainly below).

The faulty computation classifies `orders[0] = 0.25` as "certainly below `e^{−2}`" at step 5, but the true value `e^{−2} ≈ 0.135 < 0.25`, so the threshold is actually **above** `e^{−2}` and should have returned `Stop`. The voter is incorrectly granted at least one seat they did not earn. Both `implVerifyVote` and `implVerifyCert` replicate this computation and accept the inflated seat count.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-122)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Types.hs (L24-28)
```haskell
newtype LedgerStake = LedgerStake
  { unLedgerStake :: Rational
  }
  deriving (Show, Eq)
  deriving newtype (Num, HasZero)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-291)
```haskell
          let numSeats =
                localSortitionNumSeats
                  (nonPersistentCommitteeSize committee)
                  (totalNonPersistentStake committee)
                  ourStake
                  (normalizeVRFOutput vrfOutput)
          case nonZero numSeats of
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-384)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L408-430)
```haskell
implEligiblePartyVoteWeight ::
  VotingCommittee crypto WFALS ->
  EligibilityWitness crypto WFALS ->
  VoteWeight
implEligiblePartyVoteWeight committee = \case
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
  -- Non-persistent members have their voting power proportional to their
  -- number of seats granted by local sortition and their stake (normalized
  -- by the total non-persistent stake)
  WFALSNonPersistentMember
    _seatIndex
    (LedgerStake stake)
    _vrfOutput
    numSeats ->
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
     where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-534)
```haskell
              let numSeats =
                    localSortitionNumSeats
                      (nonPersistentCommitteeSize committee)
                      (totalNonPersistentStake committee)
                      voterStake
                      (normalizeVRFOutput vrfOutput)
              case nonZero numSeats of
```
