### Title
Incorrect `boundX` in `taylorExpCmpFirstNonLower` Causes Wrong Peras Local-Sortition Seat Count, Enabling Unauthorized Vote/Certificate Acceptance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Because `x = -lambda` here, the correct value is `e^lambda`. For any non-persistent voter whose Poisson parameter `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, the Taylor series terminates prematurely with a wrong result, and the seat count returned diverges from the true Poisson CDF. This incorrect count flows directly into `implVerifyVote` and `implVerifyCert` in `WFALS.hs`, where a non-zero computed seat count is the sole gate for accepting a non-persistent Peras vote or certificate. A voter whose true seat count is 0 but whose computed count is > 0 has their vote accepted without being eligible — a bypass of the Peras voting eligibility check.

---

### Finding Description

`localSortitionNumSeats` implements the local-sortition component of the wFA^LS Peras committee scheme. It determines how many non-persistent seats a voter wins by comparing their normalized VRF output against the Poisson CDF thresholds for parameter `lambda`:

```
lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake
```

The comparison is done via `taylorExpCmpFirstNonLower`, which computes `e^x` (here `x = -lambda`) via a Taylor series and stops as soon as the accumulated partial sum plus an error term certifiably exceeds or falls below each threshold. The error term at each step is:

```
errorTerm = abs (err' * boundX)
```

The function's contract is explicit:

> **IMPORTANT: `boundX` must be `e^{|x|}` for correct error bounds.** [1](#0-0) 

Because `x = -lambda`, the correct `boundX` is `e^lambda`. The call site instead passes the literal `3`: [2](#0-1) 

This is only safe when `lambda ≤ ln(3) ≈ 1.099`. For `lambda > 1.099`, `e^lambda > 3`, so `errorTerm` is underestimated. With a too-narrow error band, `decideOne` fires the `Stop` branch (`cmp >= acc' + errorTerm`) prematurely, returning a seat count that is higher than the true Poisson CDF warrants: [3](#0-2) 

The developers themselves flag this as unresolved:

> TODO(peras): evaluate whether the limit used below (3) makes sense in this context … Tracked by https://github.com/tweag/cardano-peras/issues/234 [4](#0-3) 

The inflated seat count is then used in `implVerifyVote`: [5](#0-4) 

and in `implVerifyCert`: [6](#0-5) 

In both functions, `nonZero numSeats == Nothing` is the only check that rejects an ineligible non-persistent voter. If the bug inflates a true-zero seat count to a positive value, the vote or certificate is accepted.

Additionally, `implEligiblePartyVoteWeight` scales vote weight by `numSeats`: [7](#0-6) 

An inflated `numSeats` directly inflates the voter's effective weight, potentially allowing a single pool to satisfy the quorum threshold alone.

---

### Impact Explanation

**Critical — Bypass of Peras voting/certificate eligibility check enabling unauthorized vote and certificate acceptance.**

Two concrete consequences:

1. **Ineligible vote accepted**: A non-persistent voter whose true Poisson seat count is 0 (VRF output below the threshold for 1 seat) but whose computed count is ≥ 1 due to the underestimated error bound passes the `nonZero numSeats` gate in `implVerifyVote`. Their vote is accepted and contributes to quorum.

2. **Vote weight inflation**: A voter with a true seat count of `k` may receive a computed count of `k + δ`, inflating their `VoteWeight` proportionally. If `δ` is large enough, a single pool can unilaterally forge a Peras certificate for any block it chooses, bypassing the honest-majority quorum requirement.

Both effects violate the security guarantees of the wFA^LS scheme, which depend on the Poisson CDF being evaluated exactly.

---

### Likelihood Explanation

`lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. The bug activates whenever `lambda > ln(3) ≈ 1.099`. For a committee with 100 non-persistent candidate slots, any voter holding more than ~1.1% of the non-persistent stake exceeds this threshold. Large stake pools — the most likely Peras participants — routinely hold 1–5% of total stake, placing them squarely in the affected range. The attacker does not need to control their VRF output; they only need to submit a vote in any election where the bug inflates their seat count from 0 to ≥ 1, which occurs with non-negligible probability across elections.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound. Since `x = -lambda` and `lambda` is already computed as a `FixedPoint`, pass `exp lambda` (or a safe upper-bound approximation thereof) as `boundX`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

If computing `exp lambda` in `FixedPoint` is expensive or risks overflow for large `lambda`, clamp `lambda` to a safe maximum before computing the bound, or use the known upper bound on `lambda` derived from the committee parameters. Also resolve the open issue at https://github.com/tweag/cardano-peras/issues/234.

---

### Proof of Concept

Consider a committee with `numNonPersistentVoters = 10` and a voter holding 20% of the non-persistent stake, giving `lambda = 2.0`. The correct `boundX` is `e^2 ≈ 7.389`, but `3` is used instead.

At the first Taylor step (`n=1`), `acc' = 1 + (-lambda) = -1`, `err' = (-lambda)^2 / 2 = 2`, `errorTerm = 2 * 3 = 6`. The true `errorTerm` should be `2 * 7.389 = 14.78`. The algorithm's uncertainty window `[acc' - errorTerm, acc' + errorTerm]` is `[-7, 5]` instead of the correct `[-15.78, 13.78]`.

For a threshold `orders[0] = normalizedVRFOutput / lambda` that falls in `(5, 13.78]` — i.e., a VRF output in the range `(10, 27.56]` out of the normalized `[0, 100]` range — the algorithm fires `Stop` (classifying the threshold as "not certainly below") and returns seat count 1, while the true Poisson CDF says the voter has 0 seats. The vote is accepted by `implVerifyVote` at line 381–384 of `WFALS.hs`. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L64-99)
```haskell
    -- Expected number of seats granted by local sortition
    lambda :: FixedPoint
    lambda =
      fromRational $
        fromIntegral numNonPersistentVoters
          * voterStake
          / totalNonPersistentStake

    -- Compute the "orders" of the Poisson distribution with parameter lambda,
    -- which are used as thresholds to determine how many seats we get based on
    -- the normalized VRF output
    orders :: [FixedPoint]
    orders =
      (fromRational normalizedVRFOutput / lambda)
        : zipWith
          (\k prev -> k * prev / lambda)
          [2 ..]
          orders

    -- Estimate how many seats we get by comparing the normalized VRF output
    -- against the thresholds defined by the orders.
    --
    -- TODO(peras): evaluate whether the limit used below (3) makes sense in
    -- this context. One possible starting point would be to understand why
    -- @checkLeaderNatValue@ (in Ledger) also uses 3 as its own limit when
    -- computing slot leadership proofs.
    --
    -- Tracked by this issue:
    -- https://github.com/tweag/cardano-peras/issues/234
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L421-432)
```haskell
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
      TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
        totalNonPersistentStake committee
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
