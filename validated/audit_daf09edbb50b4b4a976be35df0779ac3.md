### Title
Hardcoded `boundX = 3` in `localSortitionNumSeats` Causes Inflated Non-Persistent Seat Count, Weakening Peras Quorum Threshold — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded error-bound parameter `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error estimation. Because `x = -lambda`, the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the hardcoded `3` underestimates the true error bound, causing the Taylor-series comparison to declare thresholds "ABOVE" prematurely. The result is that a non-persistent voter is granted more committee seats than they are entitled to, inflating their `VoteWeight` and weakening the Peras quorum check.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent Peras voting seats a voter receives by comparing their normalized VRF output against Poisson CDF thresholds (`orders`) using a Taylor-series approximation of `e^{-lambda}`:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; must be e^{|x|} = e^lambda per the contract
      orders
      (-lambda)
``` [1](#0-0) 

The `taylorExpCmpFirstNonLower` function's own documentation states:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term is computed as:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `lambda > ln(3) ≈ 1.099`, `e^lambda > 3`, so `errorTerm` is smaller than it should be. The "definitely ABOVE" condition `cmp >= acc' + errorTerm` fires at a lower threshold than correct, causing the function to return an index (grant seats) when the true answer is uncertain or "BELOW". The voter is granted more seats than their VRF output and stake entitle them to. [4](#0-3) 

The inflated `numSeats` is then used directly in `implEligiblePartyVoteWeight` to compute the voter's `VoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [5](#0-4) 

The same `localSortitionNumSeats` call is made in both `implVerifyVote` and `implVerifyCert`, meaning the verifier accepts the inflated seat count without independent correction: [6](#0-5) [7](#0-6) 

The codebase itself acknowledges the `3` limit is unvalidated via a TODO comment referencing a tracked issue: [8](#0-7) 

---

### Impact Explanation

`lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. For a committee with 100 non-persistent voters, any voter holding more than ~1.1% of the non-persistent stake has `lambda > ln(3)` and receives an inflated seat count. Their `VoteWeight` is proportionally inflated. Because `stakeAboveThreshold` compares the accumulated `PerasVoteStake` against a fixed `quorumThreshold` from `PerasParams`, inflated weights allow quorum to be reached with less actual stake than the protocol requires. A single high-stake non-persistent voter could reach quorum alone, or a small coalition could do so without the required supermajority. This is a bypass of the Peras voting committee eligibility check enabling unauthorized certificate acceptance. [9](#0-8) 

---

### Likelihood Explanation

The condition `lambda > ln(3)` is met by any non-persistent voter with above-average stake in a reasonably sized committee. For example, with 100 non-persistent voters, a voter with 2% of non-persistent stake has `lambda = 2`, giving `e^2 / 3 ≈ 2.46×` underestimation of the error bound. No key compromise, admin access, or front-running is required. The voter only needs to submit a vote or certificate through the normal Peras protocol flow, which is an unprivileged operation.

---

### Recommendation

Replace the hardcoded `3` with the correct `e^lambda` value. Since `lambda` is already computed as a `FixedPoint`, compute `exp lambda` (or a safe upper bound) and pass it as `boundX`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

If computing `exp lambda` is too expensive, use a conservative upper bound that is always `>= e^lambda` for the valid range of `lambda` values (e.g., derived from the maximum possible `lambda` given protocol parameters).

---

### Proof of Concept

Consider a Peras committee with:
- `numNonPersistentVoters = 100`
- A voter holding 3% of non-persistent stake → `lambda = 3.0`
- Correct `boundX = e^3 ≈ 20.09`; used `boundX = 3`

At iteration `n` where `err' ≈ 0.01`:
- Correct `errorTerm = 0.01 * 20.09 = 0.2009`
- Actual `errorTerm = 0.01 * 3 = 0.03`

The "ABOVE" condition `cmp >= acc' + 0.03` fires ~6.7× more easily than `cmp >= acc' + 0.2009`. The function returns index `i` (granting `i` seats) when the true answer is "uncertain" or "BELOW". The voter's `VoteWeight` is multiplied by `i` instead of the correct lower value. With `i = 2` instead of `i = 1`, the voter's weight is doubled, halving the effective quorum threshold for that voter's contribution. [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L62-99)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L165-169)
```haskell
  decideOne maxN n err acc divisor cmp
    | maxN == n = Stop
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
    | otherwise = decideOne maxN (n + 1) err' acc' divisor' cmp
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
