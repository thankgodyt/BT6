### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Underestimates Error Bound for `lambda > ln(3)`, Granting Inflated Peras Voting Seats - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` in `LS.hs` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda`, the correct value is `e^lambda`. When `lambda > ln(3) ≈ 1.099`, the supplied `3 < e^lambda`, causing the Taylor-series error bound to be underestimated. This makes the "ABOVE" (Stop) condition fire too easily, granting a non-persistent Peras voter more committee seats than their stake warrants. Because `implVerifyVote` in `WFALS.hs` accepts a vote whenever `localSortitionNumSeats` returns non-zero, and `implEligiblePartyVoteWeight` scales voting power linearly by seat count, an adversary with `lambda > ln(3)` can obtain inflated voting power in the Peras committee.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent Peras committee seats a voter is entitled to via a Poisson-distribution threshold check. The Poisson parameter is:

```
lambda = numNonPersistentVoters * voterStake / totalNonPersistentStake
```

The seat count is determined by calling `taylorExpCmpFirstNonLower`, which approximates `e^{-lambda}` via Taylor series and compares it against the `orders` thresholds: [1](#0-0) 

The first argument to `taylorExpCmpFirstNonLower` is `boundX`, which the function's own contract requires to equal `e^{|x|}`: [2](#0-1) 

Here `x = -lambda`, so the correct `boundX` is `e^lambda`. The code instead passes the literal `3`. Inside `decideOne`, the error bound is computed as: [3](#0-2) 

When `boundX < e^lambda` (i.e., `lambda > ln(3) ≈ 1.099`), `errorTerm = abs(err' * boundX)` is smaller than the true remainder of the Taylor series. The "ABOVE" (Stop) condition:

```
| cmp >= acc' + errorTerm = Stop
```

fires more easily because the threshold `acc' + errorTerm` is artificially low. The function therefore returns an index `i` (seat count) earlier than it should, granting the voter more seats than their stake warrants.

The code itself acknowledges this with an open TODO: [4](#0-3) 

The `3` was copied from `checkLeaderNatValue` in `cardano-ledger`, where it is valid because `|x| = sigma * |ln(1-f)| ≤ 0.05` for typical active-slot coefficients, making `e^{0.05} ≈ 1.05 ≪ 3`. In the local sortition context, `lambda` is unbounded above `ln(3)` for any voter holding more than `ln(3)/numNonPersistentVoters` of the non-persistent stake.

---

### Impact Explanation

`implVerifyVote` in `WFALS.hs` calls `localSortitionNumSeats` to verify a non-persistent voter's eligibility and seat count: [5](#0-4) 

`implEligiblePartyVoteWeight` then multiplies the voter's stake by the inflated `numSeats`: [6](#0-5) 

A voter granted `k` extra seats receives `k × stake / totalNonPersistentStake` extra voting weight. With enough inflated weight, a single adversarial pool can push a Peras certificate over the quorum threshold without the honest-majority assumption being violated at the ledger-stake level. This constitutes a bypass of Peras voting authorization checks.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is reached whenever:

```
voterStake / totalNonPersistentStake > ln(3) / numNonPersistentVoters
```

For a committee with 10 non-persistent seats, any voter holding more than ~11% of the non-persistent stake pool triggers the bug. This is a realistic stake concentration for a mid-sized Cardano stake pool. No special privileges, leaked keys, or social engineering are required — the adversary only needs to register a pool with sufficient stake and submit a legitimately signed `WFALSNonPersistentVote`.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound `e^lambda`. Since `lambda` is already a `FixedPoint`, compute the bound using the same fixed-point exponential available in the codebase:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

Alternatively, if a conservative static bound is desired for performance, document and enforce a protocol-level cap on `lambda` (i.e., a maximum non-persistent stake concentration per voter) and choose `boundX` accordingly.

---

### Proof of Concept

**Setup:** `numNonPersistentVoters = 10`, `voterStake / totalNonPersistentStake = 0.2`, so `lambda = 2.0 > ln(3) ≈ 1.099`. The correct `boundX` is `e^2 ≈ 7.389`; the code uses `3`.

**Effect on `decideOne`:** At Taylor term `n`, `err' = x^n / n!` and `errorTerm = |err'| * 3`. The true remainder is bounded by `|err'| * e^{|x|} = |err'| * 7.389`. The underestimated `errorTerm` is `3/7.389 ≈ 40.6%` of the true bound.

**Consequence:** The condition `cmp >= acc' + errorTerm` fires when `cmp >= acc' + 0.406 * trueRemainder`. For a VRF output `cmp` that falls in the range `[acc' + 0.406R, acc' + R]` (where `R` is the true remainder), the algorithm incorrectly declares "ABOVE" and returns the current seat index, granting the voter a seat they do not deserve.

**Vote acceptance path:**
1. Adversarial pool with `lambda = 2` submits `WFALSNonPersistentVote` with a VRF output in the above range.
2. `implVerifyVote` calls `localSortitionNumSeats` → returns `k > 0` (incorrect).
3. Vote is accepted; `implEligiblePartyVoteWeight` assigns `k * stake / totalNonPersistentStake` voting weight.
4. Adversary accumulates inflated weight across multiple elections, enabling unauthorized Peras certificate acceptance. [7](#0-6) [8](#0-7)

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
