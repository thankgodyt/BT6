### Title
Hardcoded `boundX = 3` in `localSortitionNumSeats` Causes Disproportionate Non-Persistent Seat Allocation in Peras Voting Committee — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `Ouroboros.Consensus.Committee.LS`, the function `localSortitionNumSeats` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds, where `x = -lambda` and `lambda` is proportional to the voter's stake. For large-stake non-persistent voters `e^lambda >> 3`, causing the error term to be underestimated and seats to be under-counted. For small-stake voters `e^lambda < 3`, the error term is overestimated and seats are over-counted. Both the voter's eligibility check and the verifier's check use the same function, so the incorrect seat count is consistently accepted, giving small-stake voters disproportionate voting power in Peras elections.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent committee seats a voter is granted via local sortition. It computes `lambda` as the voter's proportional expected seat count:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters
    * voterStake
    / totalNonPersistentStake
```

It then calls:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- hardcoded boundX
      orders
      (-lambda)
``` [1](#0-0) 

The contract of `taylorExpCmpFirstNonLower` is explicit:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

Since `x = -lambda`, the correct `boundX` is `e^lambda`. The hardcoded `3` is only correct when `lambda = ln(3) ≈ 1.099`. For any other value of `lambda`, the error bound is wrong.

The `errorTerm` in `decideOne` is computed as:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

- When `lambda > ln(3)` (large-stake voter): `boundX = 3 < e^lambda` → `errorTerm` is underestimated → the condition `cmp < acc' - errorTerm` (BELOW) is satisfied too easily → function returns a lower seat index → **fewer seats than deserved**.
- When `lambda < ln(3)` (small-stake voter): `boundX = 3 > e^lambda` → `errorTerm` is overestimated → the condition `cmp < acc' - errorTerm` is harder to satisfy → function returns a higher seat index → **more seats than deserved**.

The developers themselves flag this as unresolved:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. ...
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
``` [4](#0-3) 

The same incorrect `localSortitionNumSeats` is called in both the voter's eligibility path (`implCheckEligibility`) and the verifier's path (`implVerifyVote`, `implVerifyCert`): [5](#0-4) [6](#0-5) 

Because both sides use the same incorrect function, the verifier consistently accepts the inflated seat count from small-stake voters.

The seat count feeds directly into vote weight computation:

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
``` [7](#0-6) 

---

### Impact Explanation

A small-stake non-persistent committee member receives more seats than their proportional stake warrants, inflating their `VoteWeight` in Peras elections. A large-stake non-persistent member receives fewer seats, reducing their `VoteWeight`. This breaks the proportional voting power guarantee of the WFA^LS scheme. In Peras, the voting committee certifies blocks to accelerate finality; a voter with inflated power can disproportionately influence which block candidate receives a certificate, weakening the stake-weighted security assumption of the Peras protocol.

This maps to: **Bypass of Peras voting checks that enables unauthorized certificate acceptance** (Critical/High).

---

### Likelihood Explanation

Any registered stake pool that qualifies as a non-persistent committee member can exploit this. The attacker needs only to hold a small amount of stake (below the persistent seat threshold) and participate in Peras elections. No key compromise, admin access, or majority stake is required. The entry path is a crafted vote message from an unprivileged peer processed by `implVerifyVote` / `implVerifyCert`.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct `e^lambda`:

```haskell
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^lambda since x = -lambda
      orders
      (-lambda)
```

This matches the documented contract of `taylorExpCmpFirstNonLower` and ensures the Taylor series error bound is correct for all stake levels, restoring proportional seat allocation.

---

### Proof of Concept

Consider a non-persistent committee with 10 expected seats and two voters:

- **Voter A (small stake):** `voterStake / totalNonPersistentStake = 0.05` → `lambda = 0.5`, `e^lambda ≈ 1.65`. Hardcoded `boundX = 3` overestimates by ~1.8×. Error term is inflated, making "certainly below" harder to establish → voter A may be awarded 1 seat when the correct Poisson threshold says 0.
- **Voter B (large stake):** `voterStake / totalNonPersistentStake = 0.5` → `lambda = 5`, `e^lambda ≈ 148`. Hardcoded `boundX = 3` underestimates by ~49×. Error term is deflated, making "certainly below" trivially easy → voter B is awarded 0 seats when the correct Poisson threshold says 1 or more.

Voter A's `VoteWeight` is inflated by `numSeats * stake / nonPersistentStake`; voter B's is zeroed out. The verifier (`implVerifyCert`) recomputes `localSortitionNumSeats` with the same hardcoded `3` and accepts voter A's certificate contribution while rejecting voter B's, permanently skewing Peras election outcomes in favor of small-stake participants.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-126)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
  a ->
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
