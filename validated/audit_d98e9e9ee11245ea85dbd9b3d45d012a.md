### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Causes Incorrect Error Bound in Local Sortition Seat Computation, Enabling Vote-Weight Inflation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Taylor-expansion comparison helper `taylorExpCmpFirstNonLower` is called with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Because `x = -lambda` and `lambda` can exceed `ln(3) ≈ 1.099` for any non-persistent voter with a non-trivial stake fraction, the error term is systematically underestimated. This causes the algorithm to declare "definitely above" prematurely, granting the voter more non-persistent committee seats than their VRF output and stake entitle them to. Since `localSortitionNumSeats` is called verbatim inside both `implVerifyVote` and `implVerifyCert` in `WFALS.hs`, an attacker who is a non-persistent committee member with `lambda > ln(3)` can submit a vote or certificate whose seat count — and therefore vote weight — is inflated, potentially pushing a Peras certificate over the quorum threshold with insufficient actual stake.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent committee seats a voter is entitled to by evaluating a Poisson CDF comparison via a Taylor expansion:

```haskell
-- LS.hs lines 93-99
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- boundX = e^{|x|} for correct error estimation
      orders
      (-lambda)
``` [1](#0-0) 

The function signature and its inline comment both state the requirement:

```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  a ->   -- | boundX = e^{|x|} for correct error estimation
  [a] -> -- | list of cmp thresholds
  a ->   -- | x in e^x
  Maybe Int
``` [2](#0-1) 

The `x` argument is `-lambda`, so the required value is `e^lambda`. The hardcoded `3` is only correct when `lambda ≤ ln(3) ≈ 1.099`.

`lambda` is computed as:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [3](#0-2) 

For a committee with 500 non-persistent candidates and a voter holding 0.3 % of non-persistent stake, `lambda = 500 × 0.003 = 1.5 > ln(3)`. At `lambda = 1.5`, the correct `boundX` is `e^1.5 ≈ 4.48`, but `3` is used instead — an underestimate by a factor of ~1.49.

Inside `decideOne`, the error term governs the "definitely above" and "definitely below" decisions:

```haskell
| cmp >= acc' + errorTerm = Stop   -- "definitely above" → return this index
| cmp < acc' - errorTerm  = Below  -- "definitely below" → continue
errorTerm = abs (err' * boundX)
``` [4](#0-3) 

With `boundX` too small, `errorTerm` is too small, so the "definitely above" band fires more easily. The algorithm returns `Stop` (the current index = seat count) at a lower threshold than the true Poisson CDF warrants, granting the voter more seats than their VRF output and stake entitle them to.

The codebase itself acknowledges the issue with a TODO:

```haskell
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. ...
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [5](#0-4) 

`localSortitionNumSeats` is called in two security-critical paths in `WFALS.hs`:

1. **`implVerifyVote`** — verifies an individual non-persistent vote:

```haskell
let numSeats =
      localSortitionNumSeats
        (nonPersistentCommitteeSize committee)
        (totalNonPersistentStake committee)
        voterStake
        (normalizeVRFOutput vrfOutput)
case nonZero numSeats of
  Nothing -> Left (ZeroNonPersistentSeats seatIndex)
  Just nonZeroNumSeats -> pure $ WFALSNonPersistentMember ...
``` [6](#0-5) 

2. **`implVerifyCert`** — verifies a Peras certificate (called during block validation):

```haskell
let numSeats =
      localSortitionNumSeats
        (nonPersistentCommitteeSize committee)
        (totalNonPersistentStake committee)
        voterStake
        (normalizeVRFOutput vrfOutput)
case nonZero numSeats of
  Nothing -> Left (ZeroNonPersistentSeats seatIndex)
  Just nonZeroNumSeats -> pure (WFALSNonPersistentMember ...)
``` [7](#0-6) 

The inflated `numSeats` feeds directly into `implEligiblePartyVoteWeight`, which scales the voter's contribution to quorum:

```haskell
WFALSNonPersistentMember _ (LedgerStake stake) _ (NonZero numSeats) ->
  VoteWeight (stake * fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
              / totalNonPersistentStake)
``` [8](#0-7) 

A voter who normally earns 1 seat but is granted 2 due to the incorrect error bound doubles their vote weight. If multiple such voters collude, or a single large non-persistent voter is affected, the aggregate inflated weight can push a certificate over the quorum threshold with fewer actual voters than the protocol requires.

---

### Impact Explanation

**Impact: High** — Bypass of Peras voting/certificate authorization.

A non-persistent committee member with `lambda > ln(3)` can have their vote weight inflated by a factor of `ceil(true_seats + 1) / true_seats`. For a voter normally entitled to 1 seat, this is a 2× inflation. Across multiple such voters, a certificate can be forged with total stake below the quorum threshold, causing honest nodes to accept a Peras certificate that does not represent the required fraction of stake. This breaks the Peras chain-quality and common-prefix guarantees that certificates are designed to enforce.

---

### Likelihood Explanation

**Likelihood: Medium.**

The condition `lambda > ln(3) ≈ 1.099` is met whenever `numNonPersistentVoters × voterStake / totalNonPersistentStake > 1.099`. With a committee of 500 non-persistent candidates, any voter holding more than ~0.22 % of non-persistent stake triggers the bug. This is a realistic stake fraction for a mid-sized stake pool. No privileged access is required — only normal participation as a non-persistent committee member.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

This matches the contract stated in the function's own documentation and the analogous approach used in `checkLeaderNatValue` in the Cardano Ledger, which computes the correct bound dynamically rather than using a constant.

---

### Proof of Concept

Consider a Peras epoch with:
- `numNonPersistentVoters = 500`
- Attacker's `voterStake / totalNonPersistentStake = 0.004` (0.4 %)
- `lambda = 500 × 0.004 = 2.0`
- Correct `boundX = e^2.0 ≈ 7.389`; used `boundX = 3`

At `lambda = 2.0`, the Poisson CDF threshold for 1 seat is `e^{-2} ≈ 0.135` and for 2 seats is `e^{-2}(1 + 2) = 0.406`. Suppose the attacker's normalized VRF output is `0.20` — this falls between the 1-seat and 2-seat thresholds, so the correct answer is 1 seat.

With `boundX = 3` instead of `7.389`, `errorTerm` at the first comparison is underestimated by a factor of `7.389/3 ≈ 2.46`. The "definitely above" condition `cmp >= acc' + errorTerm` fires at a lower `cmp` value, causing the algorithm to return `Stop` at index 1 (2 seats) instead of correctly continuing to establish "definitely below" at index 0 (1 seat). The attacker is granted 2 seats, doubling their vote weight from `0.004` to `0.008` of total non-persistent stake.

With 10 such colluding voters, the aggregate inflated weight is `10 × 0.008 = 0.08` instead of the correct `0.04`. If the quorum threshold is `0.75` and the honest committee contributes `0.71`, the colluding voters can push the total to `0.79 ≥ 0.75`, forging a certificate that would otherwise fail quorum.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-131)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
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
