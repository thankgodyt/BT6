### Title
`shelleyAfterVoting` Counts All Post-Deadline Blocks Instead of Only Stability-Window Blocks, Causing Premature Era-Transition Signal Under Chain Growth Violation - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs`)

---

### Summary

The `ShelleyTransition` counter `shelleyAfterVoting` accumulates every block whose slot is at or after the voting deadline, spanning the full `2 * swindow` (= `6k/f`) slots remaining in the epoch. The security argument, however, requires counting only blocks within the **first** stability window (`3k/f` slots) after the deadline. When Chain Growth is violated in that first window but k blocks still accumulate across the wider `6k/f` range, `singleEraTransition` returns `Just epochNo` and the HFC signals an era transition that should have been suppressed. This is the direct analog of the reported staking bug: a conditional check that should return zero/Nothing in a "deficit" state instead returns a non-zero/positive value.

---

### Finding Description

`ShelleyTransition` is a newtype wrapping a single counter:

```haskell
newtype ShelleyTransition = ShelleyTransitionInfo
  { shelleyAfterVoting :: Word32
  -- ^ The number of blocks in this epoch past the voting deadline
  -- ...
  -- 3. If we count how many blocks we have seen post deadline, and we have
  --    reached k of them, we know that that last pre-deadline block won't
  --    be rolled back anymore.
  }
``` [1](#0-0) 

In `applyHelper`, every block whose slot is `>= votingDeadline` increments this counter unconditionally:

```haskell
shelleyAfterVoting =
    (if blockSlot blk >= votingDeadline then succ else id) $
      shelleyAfterVoting tickedShelleyLedgerTransition
``` [2](#0-1) 

The voting deadline is `startOfNextEpoch - 2 * swindow`, so the counter accumulates blocks across the entire `2 * swindow = 6k/f` slot window remaining in the epoch. [3](#0-2) 

`shelleyTransition` then fires the era-transition signal as soon as `shelleyAfterVoting >= k`:

```haskell
guard $ shelleyAfterVoting >= fromIntegral k
return newPParamsEpochNo
``` [4](#0-3) 

The intended behavior (Iteration 4 of the HFC design) is to **suppress** the era transition if the stability window immediately after the voting deadline contains fewer than `k+1` blocks (a Chain Growth violation). The developers have explicitly flagged this discrepancy:

> **(TODO this is today's intended behavior, but a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window.)** [5](#0-4) 

The correct check should restrict the counter to blocks whose slot falls within `[votingDeadline, votingDeadline + swindow)`. Blocks in the second stability window (`[votingDeadline + swindow, startOfNextEpoch)`) must not be counted, because their existence does not guarantee that the last pre-deadline block is immutable — a rollback of up to `k` blocks could still reach back to the voting deadline.

---

### Impact Explanation

`singleEraTransition` is the sole mechanism by which the HFC learns that an era transition is stable and should be enacted: [6](#0-5) 

When the counter fires prematurely (k blocks counted across `6k/f` slots but fewer than k in the first `3k/f`), the HFC updates its `HardForkSummary` to include the new era, begins accepting blocks and time-translations in that era, and propagates the transition to the `EpochInfo` used by every downstream component (forecasting, mempool, leadership check). Nodes that correctly detect the Chain Growth violation and withhold the transition signal remain in the old era. The result is a **cross-era consensus split**: two sets of honest nodes disagree on which era they are in, breaking the Common Prefix property.

**Impact: High** — Hard-fork/era-transition mismatch that breaks cross-era consensus invariants for production Cardano nodes.

---

### Likelihood Explanation

Triggering the bug requires:
1. A protocol parameter update vote submitted before the voting deadline in some epoch.
2. A Chain Growth violation in the first `3k/f` slots after the deadline (fewer than k blocks produced), achievable via an eclipse attack or a sustained network partition targeting a subset of block producers.
3. At least k blocks appearing in the combined `6k/f` window (i.e., the deficit is made up in the second stability window).

On mainnet with k=2160 and f=0.05, the first stability window is 129,600 slots (36 hours). Suppressing k=2160 blocks over 36 hours while allowing them to appear in the subsequent 36 hours is a non-trivial but realistic adversarial scenario (eclipse attack on a minority of stake pools). The condition is not accidental.

**Likelihood: Medium**

---

### Recommendation

Restrict the `shelleyAfterVoting` increment to blocks whose slot falls strictly within the first stability window after the voting deadline:

```haskell
-- Only count blocks in [votingDeadline, votingDeadline + swindow)
let inStabilityWindow = blockSlot blk >= votingDeadline
                     && blockSlot blk <  votingDeadline + SlotNo swindow
shelleyAfterVoting =
    (if inStabilityWindow then succ else id) $
      shelleyAfterVoting tickedShelleyLedgerTransition
```

This aligns the implementation with the security argument documented in `civic_time.md` (Iteration 4): the transition is signalled only when Chain Growth holds in the stability window immediately following the voting deadline, ensuring the last pre-deadline block is truly immutable before the HFC acts on the governance outcome. [7](#0-6) 

---

### Proof of Concept

**Setup:** Cardano mainnet parameters — k = 2160, f = 0.05, swindow = 3k/f = 129,600 slots. Epoch length = 432,000 slots. Voting deadline = `startOfNextEpoch − 2 × 129,600 = startOfNextEpoch − 259,200`.

**Scenario:**

1. A valid protocol-parameter update (major version bump) is submitted just before the voting deadline in epoch N.
2. An adversary eclipses a target node, suppressing block production so that only **2,100 blocks** (< k = 2,160) appear in the first stability window `[votingDeadline, votingDeadline + 129,600)`.
3. Block production resumes; **100 more blocks** appear in the second stability window `[votingDeadline + 129,600, startOfNextEpoch)`.
4. The target node's `shelleyAfterVoting` counter reaches **2,200 ≥ k = 2,160**.
5. `shelleyTransition` returns `Just (N+1)` — the HFC signals the era transition.
6. Honest nodes that were not eclipsed correctly observe the Chain Growth violation (< k blocks in the first window) and suppress the transition, remaining in era N.
7. The target node enters era N+1; the rest of the network stays in era N. **Cross-era consensus split.**

The root cause is identical in structure to the reported staking bug: a conditional check (`shelleyAfterVoting >= k`) that should return `Nothing` (zero) in a deficit state (Chain Growth violation in the stability window) instead returns `Just epochNo` (non-zero) because the deficit-detection boundary is drawn too wide. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L302-321)
```haskell
newtype ShelleyTransition = ShelleyTransitionInfo
  { shelleyAfterVoting :: Word32
  -- ^ The number of blocks in this epoch past the voting deadline
  --
  -- We record this to make sure that we can tell the HFC about hard forks
  -- if and only if we are certain:
  --
  -- 1. Blocks that came in within an epoch after the 4k/f voting deadline
  --    are not relevant (10k/f - 2 * 3k/f).
  -- 2. Since there are slots between blocks, we are probably only sure that
  --    there will be no more relevant block when we have seen the first
  --    block after the deadline.
  -- 3. If we count how many blocks we have seen post deadline, and we have
  --    reached k of them, we know that that last pre-deadline block won't
  --    be rolled back anymore.
  -- 4. At this point we can look at the ledger state and see if there is
  --    a new protocol version update scheduled on the next epoch boundary,
  --    and notify the HFC that we need to transition into a new era at that
  --    point.
  }
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L715-722)
```haskell
              , shelleyLedgerTransition =
                  ShelleyTransitionInfo
                    { shelleyAfterVoting =
                        -- We count the number of blocks that have been applied after the
                        -- voting deadline has passed.
                        (if blockSlot blk >= votingDeadline then succ else id) $
                          shelleyAfterVoting tickedShelleyLedgerTransition
                    }
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L744-745)
```haskell
  votingDeadline :: SlotNo
  votingDeadline = subSlots (2 * swindow) startOfNextEpoch
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs (L192-225)
```haskell
shelleyTransition ::
  forall era proto mk.
  ShelleyCompatible proto era =>
  PartialLedgerConfig (ShelleyBlock proto era) ->
  -- | Next era's initial major protocol version
  Word16 ->
  LedgerState (ShelleyBlock proto era) mk ->
  Maybe EpochNo
shelleyTransition
  ShelleyPartialLedgerConfig{..}
  transitionMajorVersionRaw
  state =
    isTransition
      . Shelley.Inspect.pparamsUpdate
      $ state
   where
    ShelleyTransitionInfo{..} = shelleyLedgerTransition state

    -- 'shelleyLedgerConfig' contains a dummy 'EpochInfo' but this does not
    -- matter for extracting the genesis config
    genesis :: SL.ShelleyGenesis
    genesis = shelleyLedgerGenesis shelleyLedgerConfig

    k :: Word64
    k = SL.unNonZero $ SL.sgSecurityParam genesis

    isTransition :: ShelleyLedgerUpdate era -> Maybe EpochNo
    isTransition (ShelleyUpdatedPParams maybePParams newPParamsEpochNo) = do
      SL.SJust pp <- Just maybePParams
      let protVer = pp ^. SL.ppProtocolVersionL
      transitionMajorVersion <- SL.mkVersion transitionMajorVersionRaw
      guard $ SL.pvMajor protVer == transitionMajorVersion
      guard $ shelleyAfterVoting >= fromIntegral k
      return newPParamsEpochNo
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs (L235-250)
```haskell
  singleEraTransition pcfg _eraParams _eraStart ledgerState =
    -- TODO: We might be evaluating 'singleEraTransition' more than once when
    -- replaying blocks. We should investigate if this is the case, and if so,
    -- whether this is the desired behaviour. If it is not, then we need to
    -- fix it.
    --
    -- For evidence of this behaviour, replace the cased-on expression by:
    -- > @traceShowId $ shelleyTriggerHardFork pcf@
    case shelleyTriggerHardFork pcfg of
      TriggerHardForkNotDuringThisExecution -> Nothing
      TriggerHardForkAtEpoch epoch -> Just epoch
      TriggerHardForkAtVersion shelleyMajorVersion ->
        shelleyTransition
          pcfg
          shelleyMajorVersion
          ledgerState
```

**File:** docs/website/contents/references/miscellaneous/civic_time.md (L202-210)
```markdown
In order to satisfy the DespiteChainGrowthViolation requirement, today's HFC inlcudes a radical rule.

  - Silently ignore the on-chain governance --- ie the HFC continues with the current era _despite the on-chain governance outcome having signaled the transition to the next era_ --- if the stability window after the voting deadline contains less than k+1 blocks (ie violates Chain Growth).
    (TODO this is today's intended behavior, but a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window.)

  - Keep X = one stability window + Y.

  - Refuse to translate a slot/civic time that is after the enactment of a governance outcome if using a ledger state that is both less than k+1 blocks after the voting deadline and also less than one stability window past the voting deadline.
    Ledger states that are more than a stability window after the deadline but have fewer than k+1 blocks after the deadline do translations assuming the next epoch is in the same era (regardless of the actual on-chain governance outcome).
```
