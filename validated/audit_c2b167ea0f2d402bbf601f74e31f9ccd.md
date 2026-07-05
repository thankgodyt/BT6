### Title
Peras VR-1A Voting Rule Uses Wrong Round's Start Slot, Permanently Disabling the Normal Voting Path - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs`)

---

### Summary

The Peras voting rule VR-1A is evaluated using the start slot of the **certificate's own round** (`r-1`) instead of the start slot of the **current voting round** (`r`). Because a certificate for round `r-1` can only physically arrive after quorum is reached during round `r-1` — which is always later than `start(r-1) + X` given the default parameters — VR-1A fails unconditionally in practice. Every node permanently falls into the cooldown path (VR-2), disabling the normal Peras voting path entirely.

---

### Finding Description

In `mkPerasVotingView`, the helper `mkLatestCertSeenView` computes `lcsRoundStartSlot` as:

```haskell
lcsRoundStartSlot <- perasRoundStart (getPerasCertRound lcsCert)
```

`getPerasCertRound lcsCert` returns the round number of the certificate itself (round `r-1`). So `lcsRoundStartSlot` is set to `start(r-1)`. [1](#0-0) 

This value is then consumed by `perasVR1A` in `Rules.hs`:

```haskell
-- The latest certificate seen was received within X slots from the start
-- of its round
vr1a2 =
  case latestCertSeen of
    NotOrigin cert ->
      lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
``` [2](#0-1) 

The rule comment in `Rules.hs` states: *"the certificate was received in the first X slots after the start of the round."* Per CIP-0140, "the round" is the **current voting round** `r`, not the round the certificate certifies (`r-1`). The correct computation should be:

```haskell
lcsRoundStartSlot <- perasRoundStart (getPerasCertRound lcsCert + 1)
--                                                              ^^^
--                                    start of the CURRENT round r, not r-1
```

**Concrete arithmetic with default parameters:**

`PerasParams` defaults set `perasRoundLength = 90` slots and `perasCertArrivalThreshold (X) = 30` slots. [3](#0-2) 

A certificate for round `r-1` is produced only after quorum is reached during round `r-1`. Its earliest possible arrival at any peer is therefore at or after `start(r-1) + roundLength - ε = start(r) - ε`. The code's threshold is `start(r-1) + 30`. Since `start(r) - ε >> start(r-1) + 30`, the check

```
arrivalSlot  <=  start(r-1) + 30
```

is **never satisfied** for any legitimately produced certificate. VR-1A is structurally dead code.

---

### Impact Explanation

VR-1A is the first conjunct of VR-1 (the normal, non-cooldown voting path). Because it always evaluates to `False`, `perasVR1` always fails. Every node always falls through to `perasVR2` (the cooldown-exit path). This means:

1. **Normal Peras voting (VR-1) is permanently disabled.** No node ever votes via the intended happy path.
2. **Peras certificates are never produced via VR-1.** The faster-finality guarantee Peras is designed to provide is lost.
3. **Divergent voting behaviour is possible.** Nodes that receive the same certificate at slightly different wall-clock times may disagree on whether VR-2A/VR-2B pass, causing them to vote for different blocks or abstain, undermining the quorum requirement.

This constitutes a Peras voting-rule check failure that materially weakens vote authorization, matching the "Medium" impact tier: *"Public node API or miniprotocol flaw that … materially weakens block, transaction, vote, certificate, or state-query authorization."*

---

### Likelihood Explanation

The bug fires on **every Peras round** in which a certificate is produced. It is not an edge case. With `roundLength = 90` and `X = 30`, the window `[start(r-1), start(r-1)+30]` is entirely before any certificate for round `r-1` can exist. No special attacker action is required; the normal operation of the protocol triggers the bug continuously.

---

### Recommendation

In `mkLatestCertSeenView`, replace:

```haskell
lcsRoundStartSlot <- perasRoundStart (getPerasCertRound lcsCert)
```

with:

```haskell
lcsRoundStartSlot <- perasRoundStart (getPerasCertRound lcsCert + 1)
```

This computes the start of the **current voting round** (`r = cert's round + 1`), which is what VR-1A intends to check. Alternatively, pass `currRoundNo` (already available in `mkPerasVotingView`) directly into `mkLatestCertSeenView` and use `perasRoundStart currRoundNo`.

The comment in `Rules.hs` at line 151–152 should also be corrected from *"from the start of **its** round"* to *"from the start of the **current** round."*

---

### Proof of Concept

**Setup:** Peras is active. Round `r-1` completes with quorum at slot `start(r-1) + 85` (5 slots before the round ends). The certificate propagates and arrives at a peer at slot `start(r) + 5 = start(r-1) + 95`.

**VR-1A evaluation (current code):**
- `lcsRoundStartSlot = start(r-1)` ← **wrong**: uses cert's own round
- `lcsArrivalSlot = start(r-1) + 95`
- Check: `start(r-1) + 95 <= start(r-1) + 30` → **False** → VR-1A fails

**VR-1A evaluation (correct code):**
- `lcsRoundStartSlot = start(r) = start(r-1) + 90` ← correct: uses current round
- `lcsArrivalSlot = start(r-1) + 95`
- Check: `start(r-1) + 95 <= start(r-1) + 90 + 30` → **True** → VR-1A passes

The node falls into VR-2 (cooldown path) when it should vote via VR-1. Since this applies to every certificate produced in every round, the Peras normal voting path is permanently suppressed. [1](#0-0) [4](#0-3) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L127-165)
```haskell
-- | VR-1A: the voter has seen the certificate for the previous round, and the
-- certificate was received in the first X slots after the start of the round.
perasVR1A ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVR1A
  PerasVotingView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    VR1A := vr1a1 :/\: vr1a2
   where
    -- The latest certificate seen is from the previous round
    vr1a1 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          currRoundNo :==: getPerasCertRound (lcsCert cert) + 1
        -- We have never seen a certificate ==> check if we are voting in round 0
        Origin ->
          currRoundNo :==: PerasRoundNo 0

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L67-74)
```haskell

-- | Maximum number of slots to wait for after the start of a round to consider
-- a certificate valid for voting.
newtype PerasCertArrivalThreshold
  = PerasCertArrivalThreshold {unPerasCertArrivalThreshold :: Word64}
  deriving Show via Quiet PerasCertArrivalThreshold
  deriving stock Generic
  deriving newtype (Enum, Eq, Ord, NoThunks, Condense)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L167-170)
```haskell
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
```
