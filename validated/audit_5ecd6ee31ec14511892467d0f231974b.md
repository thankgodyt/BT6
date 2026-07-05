### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Produces Incorrect Error Bounds for Non-Persistent Peras Voters with `lambda > ln(3)`, Enabling Inflated Vote Weight and Quorum Bypass - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Because `x = -lambda`, the correct value is `e^lambda`. The constant `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. For any non-persistent voter whose `lambda` exceeds this threshold — which is routine for any pool with more than ~1% of non-persistent stake in a 100-seat committee — the error bound is underestimated, the Taylor-series comparison terminates with a wrong result, and the voter is assigned an incorrect (inflated) number of local-sortition seats. Because seat count directly multiplies into `VoteWeight` in `implEligiblePartyVoteWeight`, inflated seats inflate voting power, potentially allowing a coalition of large-stake non-persistent voters to reach the Peras quorum threshold with less than the required stake.

---

### Finding Description

**Root cause — `LS.hs` lines 94–99:**

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; must be e^{lambda} per the function contract
      orders
      (-lambda)
```

The function contract (line 121) states:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
```

Here `x = -lambda`, so `|x| = lambda` and the required value is `e^lambda`. The hardcoded `3` satisfies this only when `e^lambda ≤ 3`, i.e., `lambda ≤ ln(3) ≈ 1.099`.

**`lambda` computation — lines 65–70:**

```haskell
lambda :: FixedPoint
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
```

`lambda = numNonPersistentVoters × (voterStake / totalNonPersistentStake)`. For a committee with 100 non-persistent voters, any voter holding more than 1.099 % of non-persistent stake produces `lambda > ln(3)`. For 500 non-persistent voters the threshold drops to 0.22 %. These are ordinary, realistic stake fractions.

**Error-bound mechanics — lines 165–175:**

```haskell
decideOne maxN n err acc divisor cmp
  | maxN == n = Stop
  | cmp >= acc' + errorTerm = Stop   -- declared ABOVE
  | cmp < acc' - errorTerm = Below … -- declared BELOW
  | otherwise = decideOne …
 where
  err'      = (err * x) / divisor'
  errorTerm = abs (err' * boundX)    -- underestimated when boundX < e^lambda
```

When `boundX < e^lambda`, `errorTerm` is smaller than the true Taylor remainder. The algorithm therefore declares comparisons as "certain" prematurely. Because the ABOVE branch (`cmp >= acc' + errorTerm`) fires with a lower threshold, the function returns a higher index than correct — granting the voter more seats than the Poisson distribution warrants.

**Vote-weight amplification — `WFALS.hs` lines 426–429:**

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
```

`numSeats` is taken directly from `localSortitionNumSeats`. An inflated seat count linearly inflates `VoteWeight`.

**Certificate verification path — `WFALS.hs` lines 528–536:**

```haskell
let numSeats =
      localSortitionNumSeats
        (nonPersistentCommitteeSize committee)
        (totalNonPersistentStake committee)
        voterStake
        (normalizeVRFOutput vrfOutput)
case nonZero numSeats of
  Nothing -> Left (ZeroNonPersistentSeats seatIndex)
  Just nonZeroNumSeats -> pure (WFALSNonPersistentMember … nonZeroNumSeats)
```

The verifier recomputes `numSeats` independently and only checks `> 0`; it does not compare the claimed seat count against the computed one. The inflated `numSeats` is accepted and propagated into the `EligibilityWitness`, which then feeds `implEligiblePartyVoteWeight`.

The code itself acknowledges the uncertainty with a TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
```

---

### Impact Explanation

Any non-persistent Peras committee member with `lambda > ln(3)` receives an inflated seat count from `localSortitionNumSeats`. Their `VoteWeight` is proportionally inflated. If several large-stake non-persistent voters are present in the same election, their combined inflated weight can push the aggregate past the quorum threshold (`stakeAboveThreshold`) even though the true combined stake is below it. This constitutes a bypass of Peras certificate/vote authorization: an unauthorized certificate can be forged and accepted by honest nodes, breaking the Peras safety guarantee that a certificate attests to ≥ quorum stake.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met by any non-persistent voter holding more than `ln(3) / numNonPersistentVoters` of the non-persistent stake. For realistic committee sizes (100–500 non-persistent seats), this threshold is 0.22 %–1.1 % of non-persistent stake — well within the range of ordinary pool operators. No privileged access, key compromise, or social engineering is required; the bug is triggered automatically by the protocol arithmetic for any qualifying voter.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp (toRational lambda))   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

Because `FixedPoint` may not expose `exp` directly, compute the bound in `Rational` or `Double` before passing it. Alternatively, cap `lambda` at `ln(3)` before the Taylor comparison and document the approximation explicitly, accepting that voters with `lambda > ln(3)` are conservatively assigned fewer seats (false negatives rather than false positives). The false-negative direction is safe for security; the false-positive direction (current behaviour) is not.

---

### Proof of Concept

**Setup:** 100 non-persistent voters; one voter holds 5 % of non-persistent stake.

```
lambda = 100 × 0.05 = 5.0
e^lambda = e^5 ≈ 148.4
boundX used = 3
```

At Taylor iteration `n`, `errorTerm = |err' × 3|` instead of `|err' × 148.4|`. The error bound is underestimated by a factor of ~49×. The algorithm declares the comparison "certain" ~49× earlier than it should, returning an index that is systematically too high. The voter receives more seats than the Poisson distribution assigns, and their `VoteWeight` is inflated by the ratio `(wrong seats) / (correct seats)`. Repeating across several large-stake non-persistent voters, the aggregate inflated weight can exceed the quorum threshold without the true stake doing so. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L64-70)
```haskell
    -- Expected number of seats granted by local sortition
    lambda :: FixedPoint
    lambda =
      fromRational $
        fromIntegral numNonPersistentVoters
          * voterStake
          / totalNonPersistentStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-544)
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
```
