### Title
Wrong Round Used to Compute `lcsRoundStartSlot` in `mkPerasVotingView` Causes VR-1A to Always Fail - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs`)

---

### Summary

In `mkPerasVotingView`, the `lcsRoundStartSlot` field of `LatestCertSeenView` is populated using the **certificate's own round number** (`getPerasCertRound lcsCert`) instead of the **current round number** (`currRoundNo`). The field is explicitly documented as "Starting slot number of the round where this certificate was received", which is `currRoundNo`, not the cert's round. This causes the Peras VR-1A timing check to evaluate against the wrong slot boundary, making it structurally impossible to pass in normal operation. All voting is silently forced through the VR-2 (cooldown-exit) path, or suppressed entirely.

---

### Finding Description

**Root cause — `mkPerasVotingView`, line 259:**

```haskell
-- mkLatestCertSeenView (local function inside mkPerasVotingView)
lcsRoundStartSlot <- perasRoundStart (getPerasCertRound lcsCert)   -- BUG
```

`currRoundNo` is a parameter of `mkPerasVotingView` and is in scope via closure, but `mkLatestCertSeenView` ignores it and instead queries the start slot of the **cert's own round** (`certRound = currRoundNo - 1` when VR-1A's first sub-check passes).

The field contract is unambiguous:

```haskell
data LatestCertSeenView cert = LatestCertSeenView
  { ...
  , lcsRoundStartSlot :: !SlotNo
  -- ^ Starting slot number of the round where this certificate was received
  ...
  }
```

"The round where this certificate was received" is `currRoundNo`, so the correct call is:

```haskell
lcsRoundStartSlot <- perasRoundStart currRoundNo   -- correct
```

**How VR-1A consumes this value (`Rules.hs`, line 157):**

```haskell
-- vr1a2 sub-check
lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
```

VR-1A's first sub-check (`vr1a1`) already enforces `currRoundNo == getPerasCertRound cert + 1`, so when `vr1a2` is reached the cert is always from round `r = currRoundNo - 1`. A certificate for round `r` can only be produced after quorum is reached inside round `r`, so it arrives at the earliest at `start(r+1) = start(r) + roundLength`. With the bug, the check becomes:

```
arrivalSlot  <=  start(certRound) + X
             =   start(currRoundNo - 1) + X
```

Because `arrivalSlot >= start(currRoundNo) = start(certRound) + roundLength`, the check reduces to:

```
start(certRound) + roundLength  <=  start(certRound) + X
                  roundLength   <=  X
```

`X` (`perasCertArrivalThreshold`) is a small number of slots intended to measure promptness within a round, not a full round length. In any realistic parameterisation `X < roundLength`, so **`vr1a2` is structurally always `False`**, making VR-1A permanently fail regardless of how promptly the certificate was received.

**Analog to the reported Solidity bug:**  
The Solidity bug checked `lpTokenETH.lastInteractedTimestamp` (a fixed global) instead of `_token.lastInteractedTimestamp` (the parameter being validated). Here, `getPerasCertRound lcsCert` (the cert's own round, a fixed attribute of the cert) is used instead of `currRoundNo` (the round being validated against), producing the same class of wrong-object-in-validation-check error.

---

### Impact Explanation

Because VR-1A always fails:

1. **Normal voting path (VR-1) is permanently disabled.** No node running this code can ever vote via the standard "happy path", regardless of network conditions or cert timeliness.

2. **All voting is forced through VR-2 (cooldown-exit path).** VR-2A requires the latest cert seen to be at least `R` rounds old. In normal operation (cert from the previous round), VR-2A also fails, so **nodes do not vote at all** → quorum is never reached → the Peras chain enters and stays in cooldown.

3. **If VR-2 does pass** (e.g., after a genuine cooldown period), nodes vote via the cooldown-exit path when they should be voting normally. This causes incorrect block boosting: blocks that should not receive a Peras weight boost receive one (or vice versa), directly corrupting the `PerasWeightSnapshot` used by `preferAnchoredCandidate` in chain selection (`ChainSel.hs`). An honest node can thereby be made to prefer a non-canonical chain over the canonical one.

4. **Cross-node divergence.** If some nodes have the fix and others do not, their voting decisions diverge, breaking the quorum assumption and potentially splitting the Peras-boosted chain.

---

### Likelihood Explanation

The bug is deterministic and affects every invocation of `mkPerasVotingView` when a certificate has been seen. It requires no adversarial input — it fires on every normal voting attempt once Peras is activated. Any node running the Peras extension on a live or private testnet will exhibit this behaviour immediately upon the first certificate being produced.

---

### Recommendation

In `mkLatestCertSeenView` (the local `where`-clause of `mkPerasVotingView`), replace:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs
-- line 259
lcsRoundStartSlot <- perasRoundStart (getPerasCertRound lcsCert)
```

with:

```haskell
lcsRoundStartSlot <- perasRoundStart currRoundNo
```

`currRoundNo` is already a parameter of the enclosing `mkPerasVotingView` and is in scope. This aligns the implementation with the field documentation ("Starting slot number of the round **where this certificate was received**") and with the protocol intent of VR-1A (checking that the cert arrived within `X` slots of the **start of the current round**).

A property-based test should be added to `Test.Consensus.Peras.Voting.Rules` that constructs a `PerasVotingView` via `mkPerasVotingView` (rather than directly) with a cert that arrived at `start(currRound) + 1` and asserts that VR-1A passes when `X >= 1`.

---

### Proof of Concept

**Files involved:**

- `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs` — root cause
- `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs` — where the wrong value is consumed

**Step-by-step:**

1. Peras is active; a certificate for round `r` is produced and received at slot `s = start(r+1)` (the earliest possible arrival).
2. `mkPerasVotingView` is called with `currRoundNo = r+1` and `latestCertSeen = cert`.
3. Inside `mkLatestCertSeenView`:
   - `lcsArrivalSlot = s = start(r+1)`
   - `lcsRoundStartSlot = perasRoundStart (getPerasCertRound cert) = start(r)` ← **wrong**
4. `perasVR1A` evaluates `vr1a2`:
   - `lcsArrivalSlot :<=: lcsRoundStartSlot + X`
   - `start(r+1) :<=: start(r) + X`
   - `start(r) + roundLength :<=: start(r) + X`
   - `roundLength :<=: X` → **False** (since `X << roundLength`)
5. VR-1A fails. `perasVotingRules` falls through to VR-2.
6. VR-2A checks `certRound + R :<=: currRoundNo` → `r + R :<=: r+1` → **False** for any `R >= 1`.
7. Both VR-1 and VR-2 fail → node does not vote → quorum is never reached → chain enters permanent cooldown. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs (L108-120)
```haskell
-- | Slot number at the start of a Peras round
perasRoundStart ::
  PerasRoundNo ->
  PerasQry xs SlotNo
perasRoundStart roundNo = PerasQry $ do
  summary <- ask
  case HF.runQuery (HF.perasRoundNoToSlot roundNo) summary of
    Left pastHorizon ->
      throwError (PerasQryExceptionPastHorizon pastHorizon)
    Right NoPerasEnabled ->
      throwError PerasQryExceptionPerasDisabled
    Right (PerasEnabled (slotNo, _)) ->
      return slotNo
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs (L161-172)
```haskell
data LatestCertSeenView cert
  = LatestCertSeenView
  { lcsCert :: !cert
  -- ^ Latest certificate seen by the voter
  , lcsArrivalSlot :: !SlotNo
  -- ^ Slot number at which this certificate was received
  , lcsRoundStartSlot :: !SlotNo
  -- ^ Starting slot number of the round where this certificate was received
  , lcsCandidateBlockExtendsCert :: !Bool
  -- ^ Does the candidate block extend the one boosted by this certificate?
  }
  deriving Show
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs (L256-267)
```haskell
    mkLatestCertSeenView certWithProvenance = do
      let lcsCert = forgetBoostedBlockStatus certWithProvenance
      lcsArrivalSlot <- perasCertArrivalSlot lcsCert
      lcsRoundStartSlot <- perasRoundStart (getPerasCertRound lcsCert)
      let lcsCandidateBlockExtendsCert = candidateBlockExtendsCert certWithProvenance
      pure $
        LatestCertSeenView
          { lcsCert
          , lcsArrivalSlot
          , lcsRoundStartSlot
          , lcsCandidateBlockExtendsCert
          }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L151-165)
```haskell
    -- The latest certificate seen was received within X slots from the start
    -- of its round
    vr1a2 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its arrival time
        NotOrigin cert ->
          lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
        -- We have never seen a certificate ==> vacuously true
        Origin ->
          Bool True

    _X =
      SlotNo $
        unPerasCertArrivalThreshold $
          perasCertArrivalThreshold perasParams
```
