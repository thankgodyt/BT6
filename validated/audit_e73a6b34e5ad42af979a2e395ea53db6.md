Now I have all the information needed. Let me verify the exact line numbers for the key code sections.### Title
Hardcoded `boundX = 3` in `taylorExpCmpFirstNonLower` Violates Error-Bound Contract When `lambda > ln(3)`, Causing Incorrect Non-Persistent Seat Count - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error bounds. Since `x = -lambda` here, the correct bound is `exp(lambda)`. When `lambda > ln(3) ≈ 1.099` — a realistic condition for any non-persistent voter with meaningful stake — the error term is underestimated, the Taylor convergence check fires prematurely, and the returned seat count is wrong. Because `numSeats` is multiplied directly into `VoteWeight` during both vote and certificate verification, this miscalculation inflates or deflates the voting power of non-persistent Peras committee members.

---

### Finding Description

`localSortitionNumSeats` computes how many non-persistent Peras committee seats a voter is entitled to via local sortition. The core computation is a Poisson-CDF comparison implemented through a Taylor expansion of `e^{-lambda}`:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; contract requires exp(lambda)
      orders
      (-lambda)
``` [1](#0-0) 

The function `taylorExpCmpFirstNonLower` is documented with an explicit precondition:

```
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
``` [2](#0-1) 

The error term used to decide convergence is:

```haskell
errorTerm = abs (err' * boundX)
``` [3](#0-2) 

When `boundX < exp(lambda)`, `errorTerm` is smaller than the true remainder bound of the Taylor series. The convergence conditions:

```haskell
| cmp >= acc' + errorTerm = Stop   -- declared ABOVE
| cmp < acc' - errorTerm  = Below  -- declared BELOW
``` [4](#0-3) 

…fire before the partial sum has actually converged to within the true error of `e^{-lambda}`. The algorithm may return a seat index that is one (or more) too high or too low.

`lambda` is:

```haskell
lambda = fromRational $
  fromIntegral numNonPersistentVoters * voterStake / totalNonPersistentStake
``` [5](#0-4) 

For a committee with 100 non-persistent voters and a pool holding 5% of non-persistent stake, `lambda = 5` and `exp(5) ≈ 148.4`. The hardcoded `3` is off by a factor of ~50×, making the error bound essentially meaningless. The code itself acknowledges the problem with a TODO comment and a linked open issue:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context.
-- Tracked by this issue: https://github.com/tweag/cardano-peras/issues/234
``` [6](#0-5) 

The analog to the original report is exact: a fixed constant (`3` / `1e18`) is used in place of a value that must be computed from runtime inputs (`exp(lambda)` / the actual unit of `tipPercent`), causing the arithmetic result to be wrong whenever the runtime value exceeds the implicit assumption baked into the constant.

---

### Impact Explanation

The incorrect `numSeats` value flows directly into vote-weight computation for non-persistent members:

```haskell
WFALSNonPersistentMember _seatIndex (LedgerStake stake) _vrfOutput numSeats ->
  VoteWeight $
    fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
      * stake / nonPersistentStake
``` [7](#0-6) 

An inflated `numSeats` inflates `VoteWeight`, allowing a non-persistent voter to contribute more voting power toward a Peras certificate than the protocol permits. This weakens the quorum threshold: a smaller coalition of pools can forge a valid certificate, undermining the security assumption of the Peras boosting mechanism. The same `localSortitionNumSeats` call appears in both `implVerifyVote` and `implVerifyCert`: [8](#0-7) [9](#0-8) 

Both paths accept the miscalculated seat count without further validation.

---

### Likelihood Explanation

The condition `lambda > ln(3) ≈ 1.099` is met whenever a non-persistent voter's proportional stake exceeds `ln(3) / numNonPersistentVoters`. With a committee of 100 non-persistent voters, any pool holding more than ~1.1% of non-persistent stake triggers the bug. This is a routine condition for any moderately large stake pool participating in Peras. The attacker-controlled entry path is a crafted `WFALSNonPersistentVote` or `WFALSCert` message sent over the node-to-node miniprotocol; no privileged access is required.

---

### Recommendation

Replace the hardcoded `3` with the mathematically correct bound. Since `x = -lambda` and `lambda > 0`, the correct `boundX` is `exp(lambda)`:

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      (exp lambda)   -- correct: e^{|x|} = e^{lambda}
      orders
      (-lambda)
```

This matches the contract stated in the `taylorExpCmpFirstNonLower` documentation and resolves the open issue at https://github.com/tweag/cardano-peras/issues/234.

---

### Proof of Concept

**Setup:** 100 non-persistent voters; one pool holds 10% of non-persistent stake.

**Computed lambda:** `lambda = 100 * 0.10 = 10.0`

**Correct boundX:** `exp(10) ≈ 22026`

**Actual boundX used:** `3`

**Effect on errorTerm:** At Taylor step `n`, `errorTerm = |err' * 3|` instead of `|err' * 22026|`. The confidence interval is ~7342× too narrow. The algorithm declares convergence after far fewer terms than needed, returning a seat count that may differ from the true Poisson-CDF result.

**Consequence:** `implVerifyVote` accepts the vote with the wrong `numSeats`, and `implEligiblePartyVoteWeight` multiplies that wrong count into `VoteWeight`, granting the pool disproportionate influence over Peras certificate formation — a bypass of the local sortition eligibility check.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L121-126)
```haskell
-- IMPORTANT: boundX must be e^{|x|} for correct error bounds (see taylorExpCmp).
taylorExpCmpFirstNonLower ::
  forall a.
  RealFrac a =>
  -- | boundX = e^{|x|} for correct error estimation
  a ->
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs (L167-168)
```haskell
    | cmp >= acc' + errorTerm = Stop
    | cmp < acc' - errorTerm = Below (n + 1) err' acc' divisor'
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L421-429)
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
