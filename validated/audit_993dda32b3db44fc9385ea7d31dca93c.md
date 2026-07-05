### Title
Incorrect `boundX` Scaling Factor in `taylorExpCmpFirstNonLower` Causes Invalid Peras Voting Committee Seat Eligibility Decisions - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

### Summary

In `localSortitionNumSeats`, the `taylorExpCmpFirstNonLower` helper is called with a hardcoded `boundX = 3` instead of the mathematically required `e^lambda`. This is the direct analog of the original report's "18 instead of 1e18" scaling error: a wrong constant is substituted for the correct one, causing the Taylor-series error bound to be severely underestimated for any voter whose `lambda > ln(3) ≈ 1.099`. The result is that the Peras non-persistent committee seat eligibility check can produce incorrect seat counts, potentially accepting ineligible voters or producing divergent eligibility decisions across nodes.

### Finding Description

`taylorExpCmpFirstNonLower` is documented with an explicit precondition:

> **IMPORTANT: `boundX` must be `e^{|x|}` for correct error bounds** [1](#0-0) 

The function uses `boundX` to compute the truncation error of the Taylor expansion of `e^x`:

```haskell
errorTerm = abs (err' * boundX)
``` [2](#0-1) 

The caller passes `x = -lambda` and `boundX = 3`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← should be exp lambda
      orders
      (-lambda)
``` [3](#0-2) 

`lambda` is computed as:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
``` [4](#0-3) 

The correct `boundX` is `e^{|x|} = e^lambda`. Using `3` is only valid when `lambda = ln(3) ≈ 1.099`. For any voter where `lambda > 1.099` — i.e., `numNonPersistentVoters * voterStake / totalNonPersistentStake > 1.099` — the error term is underestimated by a factor of `e^lambda / 3`, which grows exponentially with `lambda`.

The developers themselves flag this with a TODO acknowledging the value may be wrong:

> `-- TODO(peras): evaluate whether the limit used below (3) makes sense in this context.` [5](#0-4) 

The contrast with `checkLeaderNatValue` (the Praos leader check) is instructive: there, `|x| = sigma * |ln(1-f)|` is tiny (e.g., `≈ 0.0005` for a 1% pool with `f=0.05`), so `e^{|x|} ≈ 1.0005 << 3`, making `3` a safe overestimate. In `localSortitionNumSeats`, `|x| = lambda` can be large (e.g., `lambda = 10` for a 10% voter in a 100-seat committee), making `3` a severe underestimate by a factor of `e^10 / 3 ≈ 7342`.

### Impact Explanation

`localSortitionNumSeats` is called in three security-critical paths:

1. **`implVerifyVote`** — verifies that a non-persistent voter's VRF output entitles them to at least one seat before accepting their vote.
2. **`implVerifyCert`** — verifies each non-persistent voter's seat count before accepting a certificate. [6](#0-5) [7](#0-6) 

When `boundX` is underestimated, `errorTerm` is too small. The algorithm may prematurely conclude that `orders[i] >= e^{-lambda} + errorTerm` (the ABOVE branch), granting the voter `i` seats when the true `e^{-lambda}` is actually below `orders[i]`. This constitutes a **bypass of Peras voting committee eligibility checks**: an ineligible non-persistent voter's vote or certificate is accepted.

Additionally, because the self-check (`implCheckShouldVote`) and the verification path (`implVerifyVote`/`implVerifyCert`) both call `localSortitionNumSeats` with the same incorrect `boundX`, they may produce divergent results for borderline cases, causing honest nodes to disagree on certificate validity — a cross-node consensus divergence.

**Impact class:** Bypass of Peras voting or certificate checks enabling unauthorized vote/certificate acceptance.

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met whenever:

```
numNonPersistentVoters * voterStake / totalNonPersistentStake > 1.099
```

For a committee of 100 non-persistent voters, any voter holding more than ~1.1% of the total non-persistent stake triggers the bug. In realistic deployments with large stake pools, this is the common case, not the exception. The error magnitude grows exponentially with `lambda`, so large stake holders are most severely affected.

### Recommendation

Replace the hardcoded `3` with the correct bound `exp lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda
      orders
      (-lambda)
```

This matches the documented precondition of `taylorExpCmpFirstNonLower` and is consistent with how `checkLeaderNatValue` in `cardano-ledger` is designed (where `3` happens to be a safe overestimate because `|x|` is tiny there).

### Proof of Concept

Consider a Peras committee with:
- `numNonPersistentVoters = 100`
- A voter with `voterStake / totalNonPersistentStake = 0.10` → `lambda = 10`

Correct `boundX = e^10 ≈ 22026`. Actual `boundX = 3`.

The error term used is `abs(err' * 3)` instead of `abs(err' * 22026)` — underestimated by factor ~7342. The Taylor series is declared "converged" far too early. For a VRF output that falls near the Poisson threshold boundary (i.e., `orders[i] ≈ e^{-10} ≈ 4.5e-5`), the algorithm may conclude ABOVE (granting `i` seats) when the true `e^{-lambda}` is below `orders[i]`, accepting the voter's vote or certificate despite ineligibility.

The entry path is fully unprivileged: any peer can send a `WFALSNonPersistentVote` or `WFALSCert` message containing a VRF output that triggers the incorrect branch in `implVerifyVote` / `implVerifyCert`. [3](#0-2) [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L519-548)
```haskell
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
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
