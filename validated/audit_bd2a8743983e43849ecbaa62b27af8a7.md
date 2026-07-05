### Title
Incorrect Taylor Expansion Error Bound (`boundX = 3`) in `localSortitionNumSeats` Enables Incorrect Non-Persistent Seat Assignment in Peras Voting Committee — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs`)

---

### Summary

`localSortitionNumSeats` calls `taylorExpCmpFirstNonLower` with a hardcoded `boundX = 3`. The function's own inline documentation states **"IMPORTANT: boundX must be e^{|x|} for correct error bounds"**. The argument `x` supplied is `-lambda`, so the correct bound is `e^{lambda}`. Whenever `lambda > ln(3) ≈ 1.099` — a condition easily reached with moderate non-persistent stake — the error term is underestimated, the Taylor-expansion comparison can resolve incorrectly, and a non-persistent voter may be assigned more (or fewer) seats than their VRF output and stake entitle them to. An inflated seat count directly inflates that voter's `VoteWeight`, potentially allowing a sub-quorum coalition to forge a Peras certificate.

---

### Finding Description

**Root cause — `LS.hs` lines 93–99:**

```haskell
expectedSeats :: Int
expectedSeats =
  fromMaybe 0 $
    taylorExpCmpFirstNonLower
      3          -- ← hardcoded; must be e^{lambda} per the function's own contract
      orders
      (-lambda)
```

`lambda` is computed