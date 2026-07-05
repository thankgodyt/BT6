### Title
Incorrect Taylor-Series Error Bound in `localSortitionNumSeats` Enables Peras Non-Persistent Committee Eligibility Bypass - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's documented contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda` (the Poisson parameter), the correct value is `exp(lambda)`. When `lambda > ln(3) ≈ 1.099` — a realistic scenario for any non-persistent voter with moderate stake in a moderately-sized committee — the error bound is underestimated, and the Taylor-series comparison can produce an incorrect result. This causes `localSortitionNumSeats` to return a non-zero seat count for a voter who should receive zero seats, bypassing the local-sortition eligibility gate used in Peras vote and certificate verification.

---

### Finding Description

`taylorExpCmpFirstNonLower` computes whether `e^x` is above or below a list of thresholds by iterating a Taylor expansion and stopping when the partial sum is provably above or below the threshold within an error bound. The error bound at each step is:

```
errorTerm = abs (err' * boundX)
```

The function's own comment is unambiguous:

> **IMPORTANT: boundX must be e^{|x|} for correct error bounds** [1](#0-0) 

The call site passes the literal `3`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- boundX: should be exp(lambda), not 3
      orders
      (-lambda)
``` [2](#0-1) 

`lambda` is the Poisson parameter for the voter:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [3](#0-2) 

For `lambda > ln(3) ≈ 1.099`, `exp(lambda) > 3`, so `boundX = 3` is strictly less than the required value. The `errorTerm` is underestimated, narrowing the "undecided" band `[acc' − errorTerm, acc' + errorTerm]`. The algorithm can then prematurely fire the `Stop` (ABOVE) branch:

```haskell
| cmp >= acc' + errorTerm = Stop   -- voter gets a seat
``` [4](#0-3) 

when the true `e^(-lambda)` is actually above `cmp` (meaning the voter should receive zero seats). The developers themselves flag this with an open TODO:

> TODO(peras): evaluate whether the limit used below (3) makes sense in this context … Tracked by https://github.com/tweag/cardano-peras/issues/234 [5](#0-4) 

The `3` was apparently copied from the Praos `checkLeaderNatValue` context, where `|x| = sigma * |ln(1-f)|` is bounded well below `ln(3)` for any realistic active-slot coefficient. That bound does **not** transfer to the local-sortition context where `lambda` is unbounded above `1`.

---

### Impact Explanation

`localSortitionNumSeats` is the sole gate for non-persistent Peras committee member eligibility. It is called in three places:

1. `implCheckShouldVote` — self-check before forging a vote
2. `implVerifyVote` — verifying an incoming non-persistent vote
3. `implVerifyCert` — verifying each non-persistent voter inside an incoming certificate [6](#0-5) [7](#0-6) 

If `localSortitionNumSeats` returns `> 0` when the correct answer is `0`, the `nonZero numSeats` check passes and the vote/certificate is accepted as coming from an eligible non-persistent member. This constitutes a **bypass of Peras voting committee eligibility verification**, allowing an unauthorized non-persistent voter's vote or certificate to be accepted by an honest node.

**Impact class:** Critical — bypass of Peras voting/certificate checks enabling unauthorized vote and certificate acceptance.

---

### Likelihood Explanation

`lambda > ln(3)` is reached whenever a voter holds more than `ln(3)/numNonPersistentVoters ≈ 1.1/N` of the total non-persistent stake. With even 10 non-persistent seats, any voter holding more than ~11% of the non-persistent stake triggers the bug. This is a realistic stake distribution.

The attacker cannot freely choose their VRF output (it is cryptographically bound to their VRF key and the election input), but they can:

1. Tune their stake to place `lambda` in a range where the underestimated error bound causes a wrong ABOVE decision for their actual VRF output.
2. Register multiple pools with different VRF keys and select the one whose output falls in the exploitable numerical region for the current election.

The attack requires offline numerical analysis but no privileged access, no key compromise, and no majority stake. **Likelihood: Medium** (requires a sophisticated attacker with moderate stake and offline computation, but no cryptographic break).

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct value `exp(lambda)`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} where x = -lambda
      orders
      (-lambda)
```

This matches the documented contract of `taylorExpCmpFirstNonLower` and is consistent with how `checkLeaderNatValue` in `cardano-ledger` computes its own `boundX` as `exp(sigma * |c|)` rather than a hardcoded constant. The open issue https://github.com/tweag/cardano-peras/issues/234 should be resolved with this fix.

---

### Proof of Concept

Consider a committee with `numNonPersistentVoters = 5` and a voter holding 30% of the non-persistent stake:

```
lambda = 5 * 0.30 = 1.5
exp(lambda) = exp(1.5) ≈ 4.48
```

The code uses `boundX = 3`, but the correct value is `≈ 4.48`. At the first Taylor step for `e^(-1.5)`:

```
acc'       ≈ 1 + (-1.5) = -0.5
err'       = (-1.5)^2 / 2 = 1.125
errorTerm  = 1.125 * 3   = 3.375   (computed, wrong)
true_error = 1.125 * 4.48 = 5.04   (correct)
```

If `orders[0]` (derived from the voter's VRF output) falls in the interval `(-0.5 + 3.375, -0.5 + 5.04) = (2.875, 4.54)`, the algorithm fires `Stop` (ABOVE → voter gets a seat) using the underestimated bound, while the correct bound would keep the comparison undecided and eventually resolve to BELOW (voter gets zero seats). The voter's vote is then accepted by `implVerifyVote` despite being ineligible. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L351-392)
```haskell
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
        let voterVRFVerificationKey =
              getVRFVerificationKey (Proxy @crypto) voterPublicKey
        let vrfContext =
              VRFVerifyContext voterVRFVerificationKey vrfOutput
        void $ bimap InvalidVoterEligibilityProof id $ do
          evalVRF
            vrfContext
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
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
