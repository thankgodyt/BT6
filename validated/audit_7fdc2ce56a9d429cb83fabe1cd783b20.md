### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Causes Incorrect Peras Non-Persistent Seat Allocation for Voters with `lambda > ln(3)` — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

The `localSortitionNumSeats` function in the Peras voting committee implementation calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda`, the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the hardcoded constant underestimates the true error bound, causing the Taylor expansion comparison to terminate early with an incorrect result. This is directly analogous to the original report's hardcoded `DENOM` constant that caused precision loss in fee calculations.

---

### Finding Description

In `localSortitionNumSeats`, the number of non-persistent Peras voting seats is determined by comparing a normalized VRF output against Poisson distribution thresholds:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- <-- hardcoded boundX
      orders
      (-lambda)
``` [1](#0-0) 

The function signature documents the contract:

```haskell
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
  a ->
``` [2](#0-1) 

The error term inside the Taylor loop is computed as:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `boundX < e^lambda`, `errorTerm` is underestimated. The ABOVE/BELOW decision conditions:

```haskell
| cmp >= acc' + errorTerm = Stop   -- fires too easily → wrong ABOVE
| cmp < acc' - errorTerm = Below … -- fires too easily → wrong BELOW
```

fire prematurely, causing `expectedSeats` to be incorrect.

`lambda` is computed as:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [4](#0-3) 

With typical Peras parameters (e.g., 100 non-persistent voters) and a voter holding just over 1% of non-persistent stake, `lambda = 100 × 0.011 = 1.1 > ln(3)`. The hardcoded `3` is therefore incorrect for any voter with more than ~1.1% of non-persistent stake when there are 100 non-persistent seats.

The developers themselves flag this as unresolved:

```haskell
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
``` [5](#0-4) 

This `localSortitionNumSeats` result is used in both vote forging (`implCheckShouldVote`) and vote/certificate verification (`implVerifyVote`, `implVerifyCert`): [6](#0-5) [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**High — Peras voting/certificate check bypass or denial.**

- If `expectedSeats` is inflated (ABOVE fires too early), a voter is granted more non-persistent seats than their stake entitles them to. They can cast proportionally more votes, potentially forging a quorum certificate with fewer legitimate participants than required. This enables unauthorized Peras certificate acceptance, which directly affects chain selection via `wsvTotalWeight` / `preferCandidate`.
- If `expectedSeats` is deflated (BELOW fires too early), a legitimate voter is denied seats they are entitled to, weakening quorum formation and potentially stalling Peras settlement.

Both directions corrupt the Peras voting committee authorization check, which is a consensus-critical operation under the allowed impact scope: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance."* [9](#0-8) 

---

### Likelihood Explanation

**Medium.** The condition `lambda > ln(3) ≈ 1.099` is met whenever `voterStake / totalNonPersistentStake > 1.099 / numNonPersistentVoters`. With 100 non-persistent seats (a plausible Peras parameter), any voter with more than ~1.1% of non-persistent stake triggers the bug. This is a routine scenario for mid-sized stake pools. No special privileges, key compromise, or majority stake are required — the attacker only needs to be a legitimate non-persistent committee candidate with ordinary stake.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `e^lambda`:

```haskell
import Cardano.Ledger.BaseTypes (fpExp)  -- or equivalent

expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (fpExp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

This mirrors the fix recommended in the original report: replace the hardcoded precision constant with one that correctly reflects the actual magnitude of the computation.

---

### Proof of Concept

Consider:
- `numNonPersistentVoters = 100`
- `voterStake / totalNonPersistentStake = 0.05` (5% of non-persistent stake)
- `lambda = 100 × 0.05 = 5.0`
- Correct `boundX = e^5 ≈ 148.4`; hardcoded `boundX = 3`

The error term at iteration `n` is `|err_n| × 148.4` (correct) vs `|err_n| × 3` (actual). The function declares convergence ~50× too early. For `lambda = 5`, the Poisson CDF thresholds are closely spaced, and premature termination can shift `expectedSeats` by 1–3 seats. A voter entitled to 5 seats might receive 7–8, allowing them to contribute disproportionate voting weight to a Peras certificate. [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L122-131)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L154-175)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-301)
```haskell
          let numSeats =
                localSortitionNumSeats
                  (nonPersistentCommitteeSize committee)
                  (totalNonPersistentStake committee)
                  ourStake
                  (normalizeVRFOutput vrfOutput)
          case nonZero numSeats of
            Nothing ->
              pure Nothing
            Just nonZeroNumSeats ->
              pure $
                Just $
                  WFALSNonPersistentMember
                    seatIndex
                    ourStake
                    vrfOutput
                    nonZeroNumSeats
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
