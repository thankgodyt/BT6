### Title
`shelleyAfterVoting` Counts All Post-Deadline Blocks Instead of Only Stability-Window Blocks, Causing Premature `TransitionKnown` Signal - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs`)

---

### Summary

The `ShelleyTransitionInfo.shelleyAfterVoting` counter accumulates every block whose slot is at or after the voting deadline, across the entire remainder of the epoch and beyond. The intended behavior — explicitly documented as a known bug in the codebase — is to count only blocks that fall within the **stability window immediately following the voting deadline**. Because the counter is over-inclusive, `singleEraTransition` can return `Just` (era transition is stable) when Chain Growth is violated in the stability window, causing the HFC to signal `TransitionKnown` prematurely and proceed with an era transition that is not yet rollback-safe.

---

### Finding Description

`ShelleyTransitionInfo` holds a single field `shelleyAfterVoting :: Word32`, described as:

> "The number of blocks in this epoch past the voting deadline"

In `applyHelper`, this counter is incremented for every block whose slot is at or after `votingDeadline`:

```haskell
shelleyLedgerTransition =
    ShelleyTransitionInfo
      { shelleyAfterVoting =
          (if blockSlot blk >= votingDeadline then succ else id) $
            shelleyAfterVoting tickedShelleyLedgerTransition
      }
``` [1](#0-0) 

The `votingDeadline` is computed as `startOfNextEpoch - 2 * swindow`, where `swindow = stabilityWindow globals = 3k/f`. [2](#0-1) 

In `shelleyTransition`, the HFC signals the era transition as stable once `shelleyAfterVoting >= k`:

```haskell
guard $ shelleyAfterVoting >= fromIntegral k
return newPParamsEpochNo
``` [3](#0-2) 

This feeds directly into `singleEraTransition`, which returns `Just epoch` (i.e., `TransitionKnown`) when the guard passes: [4](#0-3) 

The `mostRecentTransitionInfo` function in the HFC state module maps this `Just` to `TransitionKnown`:

```haskell
case singleEraTransition' cfg eraParams currentStart curState of
  Nothing -> TransitionUnknown (ledgerTipSlot curState)
  Just e  -> TransitionKnown e
``` [5](#0-4) 

`TransitionKnown` is then consumed by `reconstructSummary`, which uses it to extend the `Summary` into the next era — enabling cross-era forecasting, header validation, and `EpochInfo` construction under the next era's rules: [6](#0-5) 

**The documented bug**: `civic_time.md` (Iteration 4) explicitly states the intended behavior and the deviation:

> "Silently ignore the on-chain governance … if the stability window after the voting deadline contains less than k+1 blocks (ie violates Chain Growth). **(TODO this is today's intended behavior, but a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window.)**" [7](#0-6) 

The stability window after the voting deadline spans slots `[votingDeadline, votingDeadline + swindow)`. The current code counts blocks in `[votingDeadline, ∞)`. Blocks that fall in `[votingDeadline + swindow, startOfNextEpoch)` — the last stability window before the epoch end — are counted by the implementation but must not be counted per the intended design.

---

### Impact Explanation

When Chain Growth is violated in the stability window (fewer than k+1 blocks in `[votingDeadline, votingDeadline + swindow)`), but k+1 blocks accumulate in the broader window `[votingDeadline, startOfNextEpoch)`, the counter reaches the threshold and `singleEraTransition` returns `Just epoch`. The HFC then:

1. Emits `TransitionKnown` from `mostRecentTransitionInfo`.
2. `reconstructSummaryLedger` builds a `Summary` that includes the next era with a known start bound.
3. `epochInfoLedger` and cross-era forecasting (`mkHardForkForecast`) extend into the next era.
4. Header and block validation proceeds under the next era's rules.

If the chain is subsequently rolled back past the voting deadline (which is possible because the stability window did not contain k+1 blocks — the very condition that should have suppressed the transition), the era transition is undone. Nodes that already accepted headers/blocks under the next era's rules now hold state that diverges from the canonical chain. This is a **hard-fork era transition bug that breaks cross-era consensus invariants**: honest nodes can diverge from each other depending on whether they observed the over-counted blocks before or after the rollback.

The `ShelleyTransitionInfo` comment itself acknowledges the correct logic:

> "If we count how many blocks we have seen post deadline, and we have reached k of them, we know that that last pre-deadline block won't be rolled back anymore." [8](#0-7) 

But the implementation counts blocks beyond the stability window, which do **not** provide the same rollback guarantee for the pre-deadline block.

---

### Likelihood Explanation

This requires a Chain Growth violation in the stability window after the voting deadline — i.e., an adversary suppressing block production in `[votingDeadline, votingDeadline + swindow)` while allowing blocks in `[votingDeadline + swindow, startOfNextEpoch)`. An adversary controlling a meaningful fraction of stake (well below majority) can probabilistically suppress slots in a targeted window. The condition is reachable by an unprivileged network peer with sufficient stake, without requiring key compromise or operator fault. The likelihood is **medium**: it requires adversarial conditions but no privileged access.

---

### Recommendation

Restrict the `shelleyAfterVoting` increment to blocks whose slot falls strictly within the stability window after the voting deadline:

```haskell
shelleyAfterVoting =
    (if blockSlot blk >= votingDeadline
          && blockSlot blk < votingDeadline + swindow
       then succ
       else id) $
      shelleyAfterVoting tickedShelleyLedgerTransition
```

This aligns the implementation with the Iteration 4 specification in `civic_time.md`: only blocks in the stability window `[votingDeadline, votingDeadline + swindow)` contribute to the stability count, ensuring that `TransitionKnown` is only signaled when the governance outcome is genuinely rollback-safe.

---

### Proof of Concept

Consider `k = 2160`, `f = 1/20`, `swindow = 3k/f = 129600` slots. The voting deadline is at `startOfNextEpoch - 2 * 129600`. The stability window is `[votingDeadline, votingDeadline + 129600)`.

1. An adversary suppresses block production in the stability window, yielding only `k - 1 = 2159` blocks there.
2. In the subsequent window `[votingDeadline + 129600, startOfNextEpoch)`, normal block production resumes, adding 1 more block.
3. `shelleyAfterVoting` now equals `k = 2160`. The guard `shelleyAfterVoting >= k` passes.
4. `singleEraTransition` returns `Just nextEpoch` → `TransitionKnown`.
5. The HFC extends the `Summary` into the next era; cross-era forecasting and header validation proceed under the next era's rules.
6. A competing chain rolls back past the voting deadline (valid, since the stability window had only `k - 1` blocks, not `k + 1`).
7. Nodes that accepted next-era headers now hold divergent state; the era transition is undone on the rolled-back chain.

The root cause — `shelleyAfterVoting` counting blocks outside the stability window — is the necessary vulnerable step, directly analogous to `claimDuringForkPeriod()` not updating `remainingTokensToClaim()` in the external report: in both cases, a counter used to gate a critical state transition does not accurately reflect the true transitional state, allowing the gate to open prematurely.

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

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L741-745)
```haskell
  -- The block must come in strictly before the voting deadline
  -- See Fig 13, "Protocol Parameter Update Inference Rules", of the
  -- Shelley specification.
  votingDeadline :: SlotNo
  votingDeadline = subSlots (2 * swindow) startOfNextEpoch
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs (L218-225)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State.hs (L141-144)
```haskell
  getTransition cfg (K eraParams) Current{currentState = Flip curState, ..} = K $
    case singleEraTransition' cfg eraParams currentStart curState of
      Nothing -> TransitionUnknown (ledgerTipSlot curState)
      Just e -> TransitionKnown e
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/State/Infra.hs (L210-235)
```haskell
  go (ExactlyCons params ss) (TZ Current{..}) =
    case transition of
      TransitionKnown epoch ->
        -- We haven't reached the next era yet, but the transition is
        -- already known. The safe zone applies from the start of the
        -- next era.
        let currentEnd = History.mkUpperBound params currentStart epoch
            nextStart = currentEnd
         in case ss of
              ExactlyCons nextParams _ ->
                NonEmptyCons
                  EraSummary
                    { eraStart = currentStart
                    , eraParams = params
                    , eraEnd = EraEnd currentEnd
                    }
                  $ NonEmptyOne
                    EraSummary
                      { eraStart = nextStart
                      , eraParams = nextParams
                      , eraEnd =
                          applySafeZone
                            nextParams
                            nextStart
                            (boundSlot nextStart)
                      }
```

**File:** docs/website/contents/references/miscellaneous/civic_time.md (L201-210)
```markdown
**{Iteration 4} (latest)**.
In order to satisfy the DespiteChainGrowthViolation requirement, today's HFC inlcudes a radical rule.

  - Silently ignore the on-chain governance --- ie the HFC continues with the current era _despite the on-chain governance outcome having signaled the transition to the next era_ --- if the stability window after the voting deadline contains less than k+1 blocks (ie violates Chain Growth).
    (TODO this is today's intended behavior, but a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window.)

  - Keep X = one stability window + Y.

  - Refuse to translate a slot/civic time that is after the enactment of a governance outcome if using a ledger state that is both less than k+1 blocks after the voting deadline and also less than one stability window past the voting deadline.
    Ledger states that are more than a stability window after the deadline but have fewer than k+1 blocks after the deadline do translations assuming the next epoch is in the same era (regardless of the actual on-chain governance outcome).
```
