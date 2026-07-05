### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Peras Non-Persistent Seat Counts When `lambda > ln(3)` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` computes how many non-persistent Peras voting committee seats a voter is entitled to via a Taylor-series comparison (`taylorExpCmpFirstNonLower`). The function requires `boundX = e^{|x|}` for its error bound to be mathematically correct. The code passes the hardcoded constant `3`, which is only a valid upper bound when `lambda ≤ ln(3) ≈ 1.099`. For any voter whose `lambda > ln(3)`, the error bound is underestimated, causing the comparison to make incorrect ABOVE/BELOW decisions and return a wrong seat count. This is the direct analog of the external report's decimal-precision truncation: a fixed-precision arithmetic constant that is too small for certain input magnitudes silently produces an incorrect result, here inflating or deflating a voter's committee seat count.

---

### Finding Description

In `localSortitionNumSeats`, the Poisson-distribution seat count is computed as:

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [1](#0-0) 

`lambda` is then used as the exponent magnitude in:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3        -- <-- boundX, must equal e^{|x|} = e^lambda
      orders
      (-lambda)
``` [2](#0-1) 

The contract of `taylorExpCmpFirstNonLower` is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [3](#0-2) 

Inside `decideOne`, the error term is `abs(err' * boundX)`. When `boundX < e^lambda` (i.e., `lambda > ln(3)`), `errorTerm` is smaller than the true Taylor remainder. The two decision branches become:

```haskell
| cmp >= acc' + errorTerm = Stop   -- fires too easily → grants more seats
| cmp < acc' - errorTerm  = Below  -- fires too easily → grants fewer seats
``` [4](#0-3) 

When the ABOVE branch fires prematurely, the voter receives more seats than the Poisson distribution entitles them to. The developers themselves flag this with an open TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [5](#0-4) 

The code already handles the `lambda → 0` underflow case (analogous to the external report's 0-amount check), but leaves the `lambda > ln(3)` overestimation case unguarded:

```haskell
| lambda <= 0 = LocalSortitionNumSeats 0   -- underflow handled
-- lambda > ln(3): boundX is wrong, no guard
``` [6](#0-5) 

---

### Impact Explanation

An inflated `numSeats` flows directly into vote-weight computation in `implEligiblePartyVoteWeight`:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [7](#0-6) 

It also flows into certificate verification in `implVerifyCert`: a non-persistent voter whose seat count is inflated by the incorrect error bound passes the `nonZero numSeats` check and is accepted as a valid committee member with elevated weight:

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
    pure ( WFALSNonPersistentMember ... nonZeroNumSeats ... )
``` [8](#0-7) 

If multiple non-persistent voters with `lambda > ln(3)` each receive one extra seat, their aggregate inflated weight can push a certificate past the quorum threshold with less actual stake than required, constituting a bypass of Peras certificate verification.

---

### Likelihood Explanation

`lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake`. With a committee of 100 non-persistent seats, any voter holding more than ~1.1% of the non-persistent stake has `lambda > ln(3)`. In a realistic Cardano stake distribution with hundreds of pools, a significant fraction of non-persistent committee candidates will exceed this threshold in every epoch. The condition is not adversarially constructed; it arises naturally from normal stake distributions.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda` (or a safe upper bound derived from `lambda`):

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp (realToFrac lambda))  -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

Alternatively, clamp `lambda` to `ln(3)` before the call and document the approximation, or use the exact `e^lambda` computed via the same fixed-point arithmetic already available in the codebase.

---

### Proof of Concept

Consider a committee with:
- `numNonPersistentVoters = 5`
- `voterStake / totalNonPersistentStake = 0.3`
- `lambda = 5 * 0.3 = 1.5 > ln(3) ≈ 1.099`
- `e^lambda ≈ 4.48`, but `boundX = 3`

The error term `abs(err' * 3)` is ~33% smaller than the correct `abs(err' * 4.48)`. For a VRF output whose normalized value places `orders[1]` within the true error band around `e^{-1.5} ≈ 0.223`, the algorithm will prematurely fire the ABOVE branch and return `expectedSeats = 1` instead of `0`. The voter is then accepted by `implVerifyCert` as holding 1 non-persistent seat with vote weight `1 * stake / totalNonPersistentStake = 0.3`, when the correct weight is 0. Across all voters with `lambda > ln(3)` in the same election, the cumulative inflated weight can exceed the quorum margin, causing a Peras certificate to be accepted with insufficient true stake backing.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L56-62)
```haskell
    | voterStake <= 0 = LocalSortitionNumSeats 0
    -- If the voter has stake close to zero, the conversion from 'Rational' to
    -- 'FixedPoint' for 'lambda' might underflow to zero, which would cause the
    -- "orders" computation below to divide by zero.
    | lambda <= 0 = LocalSortitionNumSeats 0
    -- This voter might be entitled to some seats => run the local sortition.
    | otherwise = LocalSortitionNumSeats (fromIntegral expectedSeats)
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
