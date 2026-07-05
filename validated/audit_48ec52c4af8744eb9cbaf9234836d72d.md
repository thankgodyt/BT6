### Title
Hardcoded `boundX = 3` in `localSortitionNumSeats` Produces Incorrect Seat Count for Non-Persistent Committee Members When `lambda > ln(3)`, Inflating Vote Weight and Weakening Peras Quorum - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

In `localSortitionNumSeats`, the Taylor-expansion error-bound helper `taylorExpCmpFirstNonLower` is called with a hardcoded `boundX = 3`. The function's own contract requires `boundX = e^{|x|}` for correct error estimation. Because `x = -lambda` (the Poisson rate for the voter's expected seats), the correct bound is `e^lambda`. The value `3` is only valid when `lambda ≤ ln(3) ≈ 1.099`. For any non-persistent voter whose `lambda` exceeds this threshold, the error bound is underestimated, the Taylor series may terminate early with a false "ABOVE" decision, and the voter is granted more seats than the Poisson distribution warrants. The code itself flags this with an unresolved TODO comment.

---

### Finding Description

**Root cause — `LS.hs` lines 93–99:**

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; correct value is e^lambda
      orders
      (-lambda)
```

`taylorExpCmpFirstNonLower boundX cmps x` uses `errorTerm = abs(err' * boundX)` to decide whether the partial Taylor sum has converged. When `boundX < e^{|x|}`, `errorTerm` is underestimated. The early-exit condition `cmp >= acc' + errorTerm` then fires prematurely, returning `Stop` (ABOVE = seat granted) before the series has actually converged. The result is that `expectedSeats` is inflated for any voter whose `lambda > ln(3)`.

`lambda` is computed as:

```haskell
lambda =
  fromRational $
    fromIntegral numNonPersistentVoters
      * voterStake
      / totalNonPersistentStake
```

With 100 non-persistent voters, any voter holding more than `ln(3)/100 ≈ 1.1 %` of the non-persistent stake has `lambda > ln(3)`. This is a routine condition in any realistic stake distribution.

The inflated `expectedSeats` propagates directly into vote weight via `implEligiblePartyVoteWeight` (`WFALS.hs` lines 426–429):

```haskell
VoteWeight $
  fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
    * stake
    / nonPersistentStake
```

Because `localSortitionNumSeats` is called identically in both `implVerifyVote` and `implCheckShouldVote`, the inflated seat count is accepted by the verifier as well as produced by the voter — the inflation is consistent and undetected.

The code acknowledges the problem with an open TODO:

```
-- TODO(peras): evaluate whether the limit used below (3) makes sense in
-- this context. ...
-- Tracked by this issue:
-- https://github.com/tweag/cardano-peras/issues/234
```

---

### Impact Explanation

The inflated `VoteWeight` for affected non-persistent voters causes the aggregate `PerasVoteStake` accumulated in `votesReachQuorum` (`SupportsPeras.hs` lines 267–270) to exceed the quorum threshold with fewer actual votes than the protocol design requires. A coalition of non-persistent voters whose individual `lambda` values are all above `ln(3)` can forge a valid Peras certificate while contributing less real stake than the quorum threshold demands. This is a material weakening of Peras certificate authorization: certificates that should not pass `stakeAboveThreshold` do pass, because each contributing vote carries artificially elevated weight.

---

### Likelihood Explanation

The condition `lambda > ln(3)` is satisfied by any non-persistent voter holding more than `ln(3) / numNonPersistentVoters` of the non-persistent stake. For a committee with 100 non-persistent candidates this threshold is ~1.1 %; for 500 candidates it is ~0.22 %. In any realistic Cardano-like stake distribution the majority of non-persistent candidates will exceed this threshold. The bug is therefore triggered on every election involving such voters, not