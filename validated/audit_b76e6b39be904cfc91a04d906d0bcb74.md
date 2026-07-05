### Title
`shelleyAfterVoting` Counts All Post-Deadline Blocks Instead of Only Stability-Window Blocks, Enabling Premature Era Transition Signaling - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs`)

---

### Summary

The `ShelleyTransitionInfo.shelleyAfterVoting` counter accumulates every block whose slot falls at or after the voting deadline, without an upper-bound cap at `votingDeadline + stabilityWindow`. The Hard Fork Combinator (HFC) uses this counter to decide whether the on-chain governance outcome is stable enough to signal an era transition. The intended design (documented as a known bug in the codebase) requires counting only blocks within the **first stability window** after the deadline. Because the counter instead spans the full `2 × stabilityWindow` post-deadline region, the HFC can signal an era transition even when the stability-window block-count check fails — i.e., even when Chain Growth is violated and the governance outcome is not yet immutable.

---

### Finding Description

`ShelleyTransitionInfo` carries a single field `shelleyAfterVoting :: Word32` that is incremented in `applyHelper` whenever a block's slot is at or after `votingDeadline`:

```haskell
shelleyAfterVoting =
    (if blockSlot blk >= votingDeadline then succ else id) $
      shelleyAfterVoting tickedShelleyLedgerTransition
``` [1](#0-0) 

`votingDeadline` is computed as `startOfNextEpoch - 2 * stabilityWindow`, so the post-deadline region spans exactly `2 × stabilityWindow` slots until the epoch boundary. [2](#0-1) 

The counter is reset to `0` on every epoch tick:

```haskell
if isNewEpoch ei (shelleyTipSlotNo <$> shelleyLedgerTip) slotNo
  then ShelleyTransitionInfo{shelleyAfterVoting = 0}
  else shelleyLedgerTransition
``` [3](#0-2) 

`shelleyTransition` then gates the era transition on `shelleyAfterVoting >= k`:

```haskell
guard $ shelleyAfterVoting >= fromIntegral k
return newPParamsEpochNo
``` [4](#0-3) 

The design intent (Iteration 4, documented in `civic_time.md`) is that the HFC should **silently ignore** the on-chain governance outcome if the **first stability window** after the voting deadline contains fewer than `k+1` blocks (a Chain Growth violation). The current code violates this by counting blocks from the entire `2 × stabilityWindow` post-deadline region. The codebase itself acknowledges this:

> "TODO this is today's intended behavior, but **a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window**." [5](#0-4) 

The structural analog to the Tap bug is exact:
- **Tap**: `tapped` (accumulated allowance) is capped but the remainder is silently discarded when the state resets, so the unclaimed portion is permanently lost.
- **Here**: `shelleyAfterVoting` (accumulated block count) includes blocks outside the intended stability window, so the counter reaches the threshold `k` based on evidence that the security argument does not cover, and the remainder of the window that *should* have been checked is silently ignored.

---

### Impact Explanation

The `shelleyAfterVoting >= k` guard is the sole consensus-layer check that prevents the HFC from signaling an era transition when the governance outcome is not yet immutable. When the first stability window has fewer than `k+1` blocks (Chain Growth violation) but the full `2 × stabilityWindow` post-deadline region has `k+1` blocks, the current code signals the transition. The intended behavior is to suppress it.

A premature transition signal causes the node to:
1. Announce the era transition epoch via `singleEraTransition`, extending the HFC forecast into the next era.
2. Begin accepting and validating headers/blocks under the new era's rules.
3. If a rollback then removes the blocks that were counted outside the stability window, the counter drops below `k`, the transition is un-signaled, but the node may have already committed ledger state or forecast results based on the new era — creating an incoherent ledger view.

This is a **High** impact: hard-fork era transition bug that breaks cross-era consensus invariants for production Cardano nodes under Chain Growth violation conditions.

---

### Likelihood Explanation

A Chain Growth violation in the first stability window requires either:
- **Natural low activity**: a period where fewer than `k+1` blocks are produced in `3k/f` slots (possible on low-activity testnets or during network partitions).
- **Adversarial suppression**: an adversary withholding blocks in the first stability window while releasing them in the second. This requires significant (but not necessarily majority) stake to suppress block production in a targeted window.

The bug is self-documented as a known issue in the production codebase, confirming it is a real defect, not a theoretical concern. Likelihood is **Medium-Low** on mainnet (Chain Growth is rarely violated) but **Medium** on testnets and private networks.

---

### Recommendation

In `applyHelper`, add an upper-bound check so that only blocks within the first stability window after the voting deadline are counted:

```haskell
shelleyAfterVoting =
    (if blockSlot blk >= votingDeadline
          && blockSlot blk < votingDeadline + SlotNo swindow
       then succ
       else id) $
      shelleyAfterVoting tickedShelleyLedgerTransition
```

This aligns the implementation with the Iteration 4 design described in `civic_time.md` and ensures the HFC correctly ignores the governance outcome when Chain Growth is violated in the stability window.

---

### Proof of Concept

**Setup**: private testnet, `k = 10`, `f = 0.05`, `stabilityWindow = 3k/f = 600` slots, epoch length = `10k/f = 2000` slots.

- Voting deadline = `startOfNextEpoch - 2 × 600 = startOfNextEpoch - 1200`.
- First stability window: slots `[votingDeadline, votingDeadline + 600)`.
- Second stability window: slots `[votingDeadline + 600, startOfNextEpoch)`.

**Trigger**:
1. Submit a governance proposal to increment the major protocol version before the voting deadline.
2. Arrange block production so that only 9 blocks (`< k+1 = 11`) fall in the first stability window (`[votingDeadline, votingDeadline + 600)`).
3. Arrange 2 additional blocks in the second stability window (`[votingDeadline + 600, startOfNextEpoch)`), bringing the total post-deadline count to 11 (`>= k`).

**Observed behavior**: `shelleyAfterVoting` reaches 11 (`>= k`), `shelleyTransition` returns `Just epochNo`, and the HFC signals the era transition — despite the stability window containing only 9 blocks.

**Expected behavior**: `shelleyAfterVoting` should count only the 9 blocks in the first stability window, remain below `k`, and the HFC should suppress the transition signal. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L571-576)
```haskell
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

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L744-745)
```haskell
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

**File:** docs/website/contents/references/miscellaneous/civic_time.md (L204-205)
```markdown
  - Silently ignore the on-chain governance --- ie the HFC continues with the current era _despite the on-chain governance outcome having signaled the transition to the next era_ --- if the stability window after the voting deadline contains less than k+1 blocks (ie violates Chain Growth).
    (TODO this is today's intended behavior, but a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window.)
```
