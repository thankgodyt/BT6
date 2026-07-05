### Title
`shelleyAfterVoting` Overcounts Post-Deadline Blocks Beyond the Stability Window, Enabling Premature Era Transition Signaling Under Chain Growth Violation — (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs`)

---

### Summary

The `shelleyAfterVoting` counter in `ShelleyTransition` counts **all** blocks whose slot is at or after the voting deadline, including blocks that fall beyond the stability window (`3k/f` slots after the deadline). The intended behavior — explicitly documented as a known bug in the codebase — is to count only blocks within the stability window after the deadline. Because the check `shelleyAfterVoting >= k` in `shelleyTransition` is the sole gate for reporting `TransitionKnown` to the Hard Fork Combinator (HFC), this overcounting allows the HFC to prematurely signal an era transition as stable when Chain Growth was violated in the critical stability window. This is the direct analog of the "Fee Update Delay Bypass": a delay/stability requirement that should block an update for a full window can be satisfied by spreading the required count across a longer, less-secure interval.

---

### Finding Description

**Root cause — `applyHelper` in `Ledger.hs`:**

```haskell
shelleyAfterVoting =
    (if blockSlot blk >= votingDeadline then succ else id) $
      shelleyAfterVoting tickedShelleyLedgerTransition
```

The `votingDeadline` is `startOfNextEpoch - 2 * swindow` (where `swindow = 3k/f`). Every block whose slot falls anywhere in the range `[votingDeadline, endOfEpoch)` increments the counter — a window of `2 * swindow` slots. The counter resets to `0` on each epoch tick. [1](#0-0) [2](#0-1) 

**Gate check — `shelleyTransition` in `ShelleyHFC.hs`:**

```haskell
guard $ shelleyAfterVoting >= fromIntegral k
return newPParamsEpochNo
```

Once `shelleyAfterVoting >= k`, `singleEraTransition` returns `Just epoch`, causing the HFC to record `TransitionKnown epoch` and extend the `EpochInfo`/`Summary` into the next era. [3](#0-2) 

**Intended behavior (self-documented bug):**

The `civic_time.md` design document explicitly states:

> *(TODO this is today's intended behavior, but **a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window**.)*

The intended behavior is: if the stability window (`3k/f` slots) immediately after the voting deadline contains fewer than `k+1` blocks (a Chain Growth violation), the HFC should **silently ignore** the transition. The current code cannot detect this condition because it counts blocks across the full `2 * swindow` post-deadline window, not just the first `swindow` slots. [4](#0-3) 

**`ShelleyTransition` semantics:**

The comment on `shelleyAfterVoting` explains the intended invariant: k post-deadline blocks guarantee the last pre-deadline block is immutable, so the voting outcome cannot be rolled back. But this guarantee only holds if those k blocks are within the stability window — Chain Growth ensures `k` blocks appear in `3k/f` slots. If the k blocks are spread across `2 * swindow` slots, Chain Growth may have been violated in the first `swindow` slots, meaning the pre-deadline state is not necessarily immutable. [5](#0-4) 

**Epoch-tick reset:**

The counter resets to `0` on every epoch boundary tick, so the overcounting is scoped to the current epoch's post-deadline window. [6](#0-5) 

**HFC consequence — `reconstructSummaryLedger`:**

When `singleEraTransition` returns `Just epoch`, `mostRecentTransitionInfo` records `TransitionKnown epoch`, and `reconstructSummary` extends the `Summary` into the next era. This `Summary` is used for all `EpochInfo` queries, time/slot translations, and cross-era forecasting. [7](#0-6) [8](#0-7) 

**Monotonicity invariant violation:**

The HFC contract for `singleEraTransition` requires it to be monotonic: once it returns `Just`, it must never return `Nothing` for a later ledger state on the same chain. If the premature `TransitionKnown` is followed by a rollback that removes some of the k counted blocks (bringing `shelleyAfterVoting` below `k`), `singleEraTransition` returns `Nothing` again. This violates the invariant, causing the `EpochInfo` to change retroactively. [9](#0-8) 

---

### Impact Explanation

**Impact: High — Hard-fork era transition / ledger-view / chain-selection bug.**

Under a Chain Growth violation in the stability window after the voting deadline, the HFC prematurely signals `TransitionKnown` for an era transition. This causes:

1. **Incorrect `EpochInfo` and `Summary`**: The node constructs time/slot translations and forecasts that assume the era transition will occur at epoch `E`. These are used for leadership checks, header validation, and transaction validity-interval checks.

2. **Monotonicity invariant violation**: If a rollback subsequently removes enough post-deadline blocks to bring `shelleyAfterVoting` below `k`, `singleEraTransition` returns `Nothing`, changing the `EpochInfo`. The node may then reject valid headers (false alarms) or accept invalid ones (missed alarms) because the era boundary it uses for validation has shifted.

3. **Cross-era consensus divergence**: A node that prematurely accepted `TransitionKnown` and a node that correctly ignored the transition (because it counted only stability-window blocks) will construct different `EpochInfo` objects. This can cause them to disagree on which era a given slot belongs to, breaking cross-era header validation and chain selection.

This matches the allowed impact: *"Hard-fork, era transition, ledger-view, query, or network-version mismatch that breaks cross-era consensus or ledger invariants for production Cardano nodes."*

---

### Likelihood Explanation

**Likelihood: Low.**

The attack requires an adversary to suppress honest block production in the `3k/f`-slot stability window immediately after the voting deadline (a Chain Growth violation), while still producing `k` blocks spread across the full `2 * swindow` post-deadline window. This requires the adversary to control a substantial fraction of stake (approaching but not necessarily exceeding 50%). On Cardano mainnet with `k=2160` and `f=0.05`, the stability window is `3*2160/0.05 = 129600` slots (~1.5 days). Suppressing honest blocks for this duration is a significant adversarial capability. The bug is self-documented and known to the development team, suggesting it has not been exploited in practice.

---

### Recommendation

In `applyHelper`, restrict the `shelleyAfterVoting` increment to blocks whose slot falls within the stability window after the voting deadline, i.e., `blockSlot blk >= votingDeadline && blockSlot blk < votingDeadline + swindow`. This ensures that `shelleyAfterVoting >= k` implies Chain Growth held in the stability window, making the pre-deadline state genuinely immutable before the HFC reports `TransitionKnown`.

Alternatively, record the slot of the first post-deadline block and only count blocks within `swindow` slots of that first block, matching the intended semantics described in `civic_time.md`.

---

### Proof of Concept

**Private testnet sequence** (no mainnet required):

1. Configure a Cardano testnet with small `k` (e.g., `k=10`) and `f=0.5`, giving `swindow = 60` slots and `votingDeadline = epochEnd - 120`.

2. Submit a valid protocol version update proposal before the voting deadline.

3. After the voting deadline, suppress honest block production for the first 60 slots (the stability window). Produce 0 honest blocks in `[votingDeadline, votingDeadline + 60)`.

4. In the second half of the post-deadline window (`[votingDeadline + 60, epochEnd)`), produce `k = 10` blocks. The `shelleyAfterVoting` counter reaches 10.

5. Observe that `shelleyTransition` returns `Just (nextEpoch)` — `TransitionKnown` is set — even though Chain Growth was violated in the stability window.

6. Roll back 5 of those 10 blocks (within the rollback limit). `shelleyAfterVoting` drops to 5, `singleEraTransition` returns `Nothing`. The `EpochInfo` changes retroactively, violating the monotonicity invariant.

7. Observe that headers previously validated against the (incorrect) `TransitionKnown` `EpochInfo` are now rejected or produce inconsistent results under the updated `EpochInfo`.

### Citations

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L300-321)
```haskell
-- | Information required to determine the hard fork point from Shelley to the
-- next ledger
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

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L570-576)
```haskell
          , tickedShelleyLedgerTransition =
              -- The voting resets each epoch
              if isNewEpoch ei (shelleyTipSlotNo <$> shelleyLedgerTip) slotNo
                then
                  ShelleyTransitionInfo{shelleyAfterVoting = 0}
                else
                  shelleyLedgerTransition
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Abstract/SingleEraBlock.hs (L99-114)
```haskell
  -- | Era transition
  --
  -- This should only report the transition point once it is stable (rollback
  -- cannot affect it anymore).
  --
  -- Since we need this to construct the 'HardForkSummary' (and hence the
  -- 'EpochInfo'), this takes the /partial/ config, not the full config
  -- (or we'd end up with a catch-22).
  singleEraTransition ::
    PartialLedgerConfig blk ->
    -- | Current era parameters
    EraParams ->
    -- | Start of this era
    Bound ->
    LedgerState blk mk ->
    Maybe EpochNo
```
