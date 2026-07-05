### Title
Incorrect Taylor Series Error Bound in Local Sortition Seat Assignment Causes Incorrect Non-Persistent Vote Eligibility Decisions - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own documentation states `boundX` **must** equal `e^|x|` for correct error bounds, where `x = -lambda`. For any non-persistent committee voter whose `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, potentially causing the Taylor series comparison to terminate early with an incorrect seat count. The code itself acknowledges this with an open TODO tracked at https://github.com/tweag/cardano-peras/issues/234.

### Finding Description

In `localSortitionNumSeats`, the Poisson-based local sortition check proceeds in two arithmetic stages, each introducing precision loss:

**Stage 1 — `lambda` computation with `Rational → FixedPoint` truncation:**

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
```

The division `voterStake / totalNonPersistentStake` is performed in `Rational`, then truncated to `FixedPoint` via `fromRational`. This is the first rounding step.

**Stage 2 — `orders` list built by repeated `FixedPoint` divisions:**

```haskell
orders :: [FixedPoint]
orders =
  (fromRational normalizedVRFOutput / lambda)
    : zipWith
      (\k prev -> k * prev / lambda)
      [2 ..]
      orders
```

`normalizedVRFOutput` is itself a `Rational` (computed as `signatureNatural / signatureNaturalMax` in `BLS.hs`) converted to `FixedPoint`, then divided by the already-rounded `lambda`. Each recursive term `k * prev / lambda` introduces another `FixedPoint` division. This is the direct analog of the external report's sequential-division rounding chain.

**Stage 3 — Taylor series comparison with wrong error bound:**

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; MUST be e^|x| = e^lambda per the function's contract
      orders
      (-lambda)
```

The `taylorExpCmpFirstNonLower` contract (line 121) states:

> `IMPORTANT: boundX must be e^{|x|} for correct error bounds`

The `errorTerm` used to decide early termination is:

```haskell
errorTerm = abs (err' * boundX)
```

With `boundX = 3` instead of `e^lambda`:
- For `lambda = 2` (e.g., 200 non-persistent seats, voter holds 1% of non-persistent stake): correct bound is `e^2 ≈ 7.39`, used bound is `3` — **2.5× underestimate**.
- For `lambda = 5` (e.g., 500 non-persistent seats, voter holds 1%): correct bound is `e^5 ≈ 148.4` — **49× underestimate**.

An underestimated `errorTerm` causes the algorithm to declare a comparison "ABOVE" (`Stop`) or "BELOW" prematurely, before the partial sum has actually converged past the threshold. This produces an incorrect `expectedSeats` value.

The threshold for `lambda > ln(3)` is crossed whenever:

```
voterStake / totalNonPersistentStake > ln(3) / numNonPersistentVoters
```

For a 500-seat committee this is any voter with **>0.22% of non-persistent stake** — a routine condition.

### Impact Explanation

`localSortitionNumSeats` is called in two security-critical paths:

1. **`implVerifyVote`** (WFALS.hs, lines 375–390): determines whether an incoming non-persistent vote is accepted or rejected. An incorrect `numSeats = 0` causes a valid vote to be rejected with `ZeroNonPersistentSeats`; an incorrect `numSeats > 0` causes an ineligible vote to be accepted.

2. **`implVerifyCert`** (WFALS.hs, lines 528–543): same computation repeated for each non-persistent voter in a certificate. An incorrect seat count here causes a valid Peras certificate to be rejected or an invalid one to be accepted.

Because the incorrect seat count is deterministic given the same inputs, different nodes running the same code will agree. However, if the correct seat count differs from what the protocol specification requires, the node accepts/rejects votes and certificates that a spec-compliant implementation would not, constituting a **vote/certificate authorization bypass** and a potential **cross-node consensus divergence** if any node runs a corrected implementation.

The downstream `implEligiblePartyVoteWeight` uses `numSeats` directly to scale vote weight:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
```

An inflated `numSeats` grants a voter disproportionate voting power, potentially allowing a minority-stake coalition to reach quorum for a Peras certificate.

### Likelihood Explanation

Any non-persistent committee member with `lambda > ln(3)` is affected. For typical Peras committee sizes (hundreds of non-persistent seats), this threshold is crossed by any pool holding more than a fraction of a percent of non-persistent stake — a normal condition for mid-to-large stake pools. The attacker does not need to craft any special input; the wrong error bound fires automatically for their naturally-produced VRF output whenever the partial sum lands within the true (but underestimated) error interval.

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound. Since `x = -lambda` and `lambda > 0`, the correct `boundX` is `e^lambda`:

```haskell
-- Compute e^lambda as the correct error bound for taylorExpCmpFirstNonLower
-- (required: boundX = e^{|x|} where x = -lambda)
let eLambda = exp lambda  -- FixedPoint exponentiation

expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      eLambda   -- correct bound, not hardcoded 3
      orders
      (-lambda)
```

Alternatively, defer to the same approach used by `checkLeaderNatValue` in `cardano-ledger`, which uses exact rational arithmetic for the comparison rather than a fixed-precision Taylor approximation with a manually supplied error bound.

### Proof of Concept

Consider a Peras committee with `numNonPersistentVoters = 500` and a voter holding 2% of non-persistent stake:

```
lambda = 500 * 0.02 / 1.0 = 10.0
e^lambda = e^10 ≈ 22026
boundX used = 3  (≈ 7334× underestimate)
```

In `decideOne`, `errorTerm = |err' * 3|` instead of `|err' * 22026|`. At iteration `n` where the partial sum `acc'` is within the true error interval `[cmp - |err'*22026|, cmp + |err'*22026|]` but outside the underestimated interval `[cmp - |err'*3|, cmp + |err'*3|]`, the algorithm prematurely returns `Stop` (ABOVE) or `Below`, producing an incorrect `expectedSeats`. A voter whose true Poisson threshold places them at exactly 0 seats may be granted 1 or more seats, and their vote accepted by `implVerifyVote` with `nonZero numSeats` succeeding where it should fail. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-175)
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
taylorExpCmpFirstNonLower boundX cmps x =
  goList 1000 0 x 1 1 0 cmps
 where
  -- Traverse the list of cmps, advancing the Taylor state as needed while
  -- checking if the current cmp is ABOVE or BELOW. If ABOVE, return the index.
  goList ::
    Int -> -- maxN
    Int -> -- n
    a -> -- err
    a -> -- acc
    a -> -- divisor
    Int -> -- current index
    [a] -> -- remaining cmps
    Maybe Int
  goList _ _ _ _ _ _ [] = Nothing
  goList maxN n err acc divisor i (cmp : rest) =
    case decideOne maxN n err acc divisor cmp of
      Stop ->
        Just i
      Below n' err' acc' divisor' ->
        goList maxN n' err' acc' divisor' (i + 1) rest

  -- Decide current cmp by advancing the shared Taylor state as needed.
  -- If BELOW is established, returns the *advanced* state to continue with.
  -- If ABOVE is established or maxN reached, returns Stop.
  decideOne ::
    Int -> -- maxN
    Int -> -- n
    a -> -- err
    a -> -- acc
    a -> -- divisor
    a -> -- cmp
    Step a
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-392)
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
    | otherwise ->
        Left (NotANonPersistentMember seatIndex)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L347-354)
```haskell
-- | Create a normalized VRF output from a BLS signature
toNormalizedVRFOutput ::
  Signature VRF ->
  NormalizedVRFOutput
toNormalizedVRFOutput sig =
  NormalizedVRFOutput $
    fromIntegral (signatureNatural sig)
      / fromIntegral signatureNaturalMax
```
