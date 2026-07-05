### Title
Hardcoded Taylor Error Bound Causes Incorrect Local Sortition Seat Count, Enabling Ineligible Non-Persistent Committee Member Vote Acceptance - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda`, the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the error bound is underestimated, causing the Taylor-series comparison to terminate with an incorrect seat count. This incorrect count propagates into `implVerifyVote` and `implVerifyCert` in `WFALS.hs`, where a non-zero seat count is the sole gate for accepting a non-persistent committee member's vote or certificate.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent Peras/Leios voting committee seats a voter is entitled to, using a Poisson CDF comparison via a Taylor expansion:

```haskell
-- LS.hs lines 94-99
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- hardcoded boundX
      orders
      (-lambda)
``` [1](#0-0) 

The function's documented contract is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term inside `decideOne` is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

With `x = -lambda`, the correct `boundX` is `e^lambda`. The hardcoded `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. For any larger `lambda`, `e^lambda > 3`, so `errorTerm` is underestimated. The algorithm then makes premature "ABOVE" or "BELOW" decisions before the Taylor series has converged sufficiently, producing an incorrect `expectedSeats` value.

`lambda` is computed as:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [4](#0-3) 

For a committee with 20 non-persistent seats and a voter holding 10% of non-persistent stake, `lambda = 2.0 > 1.099`. For 100 non-persistent seats and 2% stake, `lambda = 2.0`. These are entirely realistic parameters.

---

### Impact Explanation

The incorrect `expectedSeats` value is used in two certificate/vote verification paths in `WFALS.hs`:

**`implVerifyVote`** (lines 375–390): calls `localSortitionNumSeats` and rejects the vote only if `nonZero numSeats` returns `Nothing` (i.e., zero seats). An incorrect non-zero result causes an ineligible voter's vote to be accepted. [5](#0-4) 

**`implVerifyCert`** (lines 528–548): same gate — `localSortitionNumSeats` is called per non-persistent voter in the certificate, and a non-zero result is required for acceptance. [6](#0-5) 

When `lambda > ln(3)`, the underestimated error bound causes the Taylor comparison to fire the "ABOVE" branch (`cmp >= acc' + errorTerm`) prematurely. This can return a non-zero index for a voter whose VRF output should have yielded zero seats, bypassing the eligibility gate entirely. The result is acceptance of votes and certificates from ineligible non-persistent committee members — a bypass of committee eligibility verification.

---

### Likelihood Explanation

**High.** The condition `lambda > ln(3) ≈ 1.099` is met whenever:

```
numNonPersistentVoters * (voterStake / totalNonPersistentStake) > 1.099
```

For any committee with more than ~11 non-persistent seats where a single voter holds more than 10% of non-persistent stake, or any committee with 100 seats where a voter holds more than ~1.1% of stake, the bug is active. These are normal operating conditions for a production Peras/Leios deployment. An adversary who controls a pool with sufficient non-persistent stake can craft a VRF output that lands in the region where the incorrect error bound changes the seat-count decision from 0 to ≥1.

---

### Recommendation

Replace the hardcoded `3` with the correct `e^lambda` value. Since `lambda` is a `FixedPoint`, compute `exp lambda` using the same fixed-point arithmetic before calling `taylorExpCmpFirstNonLower`:

```haskell
-- Correct: boundX = e^{|x|} = e^lambda
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- was: 3
      orders
      (-lambda)
```

This matches the documented contract of `taylorExpCmpFirstNonLower` and ensures the error bound is valid for all values of `lambda`.

---

### Proof of Concept

**Setup**: Non-persistent committee with `numNonPersistentVoters = 20`, voter holds 10% of non-persistent stake → `lambda = 2.0`.

**Correct bound**: `e^2.0 ≈ 7.389`. Error term at each Taylor step uses `7.389`.

**Actual bound**: `3`. Error term at each Taylor step uses `3`.

**Effect**: At Taylor step `n`, `err' = (-lambda)^n / n!`. For `lambda = 2`, `n = 3`:
- `err' = (-2)^3 / 6 = -8/6 ≈ -1.333`
- Correct `errorTerm = |(-1.333) * 7.389| ≈ 9.85` → algorithm continues (uncertain)
- Actual `errorTerm = |(-1.333) * 3| ≈ 4.0` → algorithm may fire "ABOVE" prematurely

A voter whose VRF output places them at the boundary of the 0-seat/1-seat threshold will receive `expectedSeats = 1` under the buggy bound but `expectedSeats = 0` under the correct bound. Submitting a `WFALSNonPersistentVote` with this VRF output passes `implVerifyVote`'s `nonZero numSeats` check, accepting an ineligible vote. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L56-99)
```haskell
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
