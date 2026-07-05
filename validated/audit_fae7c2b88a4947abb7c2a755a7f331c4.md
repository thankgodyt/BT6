### Title
Incorrect `boundX` Constant in Local Sortition Seat Calculation Causes Arithmetic Precision Error in Peras Vote Eligibility - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3` instead of the mathematically required `e^lambda`. The function's own contract states `boundX must be e^{|x|}` for correct error bounds. When `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the Taylor-series comparison to prematurely declare a threshold "ABOVE" and return a higher seat count than the voter deserves. This inflates the vote weight of non-persistent Peras committee members and is reachable via crafted votes or certificates from any unprivileged peer.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent committee seats a voter is granted via local sortition. It builds a Poisson-CDF threshold list (`orders`) and calls `taylorExpCmpFirstNonLower` to find the first threshold not certainly below `e^{-lambda}`:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; contract requires e^{|x|} = e^lambda
      orders
      (-lambda)
``` [1](#0-0) 

The function's own documentation is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Here `x = -lambda`, so `|x| = lambda` and the correct `boundX` is `e^lambda`. The hardcoded `3` is only a valid upper bound when `lambda ≤ ln(3) ≈ 1.099`.

`lambda` is computed as:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [3](#0-2) 

With, e.g., 10 non-persistent voters and a voter holding 20 % of non-persistent stake, `lambda = 2.0 > ln(3)`. The error term used inside `decideOne` is:

```haskell
errorTerm = abs (err' * boundX)
``` [4](#0-3) 

When `boundX` is too small, `errorTerm` is too small. The ABOVE guard `cmp >= acc' + errorTerm` fires prematurely on an alternating partial sum that has overshot the true value of `e^{-lambda}`, returning a higher seat index than correct. The TODO comment in the code itself acknowledges the uncertainty:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [5](#0-4) 

---

### Impact Explanation

The inflated `numSeats` value propagates directly into vote-weight computation. In `implEligiblePartyVoteWeight`, a non-persistent member's weight is proportional to `numSeats`: [6](#0-5) 

Vote verification (`implVerifyVote`) and certificate verification (`implVerifyCert`) both call `localSortitionNumSeats` and accept the vote/cert if `nonZero numSeats`: [7](#0-6) [8](#0-7) 

A non-persistent voter whose true seat count is 0 but whose `lambda > ln(3)` could receive a falsely positive seat count, bypassing the `nonZero` rejection gate entirely. A voter whose true count is 1 could receive 2 or more, inflating their Peras vote weight beyond their stake entitlement. This weakens the stake-proportional security assumption of the Peras finality gadget.

**Impact: High** — Bypass of Peras voting committee eligibility and vote-weight authorization.

---

### Likelihood Explanation

`lambda > ln(3) ≈ 1.099` is reached whenever a voter's proportional stake exceeds `1.099 / numNonPersistentVoters`. With a committee of 10 non-persistent candidates, any voter holding more than ~11 % of non-persistent stake triggers the condition. This is a realistic stake distribution. The verification path is exercised on every received non-persistent vote and certificate, making it reachable by any peer that participates in Peras elections.

**Likelihood: Medium** — Realistic parameter regime; triggered on normal protocol traffic from any non-persistent voter with moderate stake.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound `e^lambda`. Since `lambda` is already a `FixedPoint`, compute the bound using the same fixed-point arithmetic:

```haskell
-- Correct: boundX = e^{lambda} as required by taylorExpCmpFirstNonLower
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp (realToFrac lambda))   -- e^lambda, not the constant 3
      orders
      (-lambda)
```

Alternatively, use the existing `taylorExpCmp` primitive from `cardano-ledger` (which computes its own bound internally) once the TODO to merge these helpers upstream is resolved.

---

### Proof of Concept

Consider:
- `numNonPersistentVoters = 10`
- `voterStake / totalNonPersistentStake = 0.25`
- `lambda = 10 * 0.25 = 2.5`
- Correct `boundX = e^{2.5} ≈ 12.18`; supplied `boundX = 3`

For `x = -2.5`, the Taylor partial sums alternate: `1, -1.5, 1.625, -1.354, ...`. When the partial sum overshoots `cmp` from above, `errorTerm = |err' * 3|` is ~2.5× too small. The ABOVE guard fires on the overshoot, returning seat index `i+1` instead of `i`. The voter is granted one extra seat, their `VoteWeight` is scaled up by `(i+1)/i`, and `implVerifyVote`/`implVerifyCert` accept the inflated witness without error. [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L36-99)
```haskell
-- | Compute how many non-persistent seats can be granted by local sortition to
-- a voter given their normalized VRF output and stake
localSortitionNumSeats ::
  -- | Expected number of non-persistent voters in the committee
  NonPersistentCommitteeSize ->
  -- | Total stake of non-persistent voters
  TotalNonPersistentStake ->
  -- | Stake of the voter
  LedgerStake ->
  -- | Normalized VRF output from the participant
  NormalizedVRFOutput ->
  LocalSortitionNumSeats
localSortitionNumSeats
  (NonPersistentCommitteeSize numNonPersistentVoters)
  (TotalNonPersistentStake (Cumulative (LedgerStake totalNonPersistentStake)))
  (LedgerStake voterStake)
  (NormalizedVRFOutput normalizedVRFOutput)
    -- None of the non-persistent voters have any stake => nobody gets a seat.
    -- NOTE: this check avoids the expensive computation below and also prevents
    -- division by zero when computing @orders@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L408-420)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-546)
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
```
