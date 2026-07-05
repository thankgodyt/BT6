### Title
`shelleyAfterVoting` Counts All Post-Deadline Blocks Instead of Only Those in the Stability Window, Enabling Premature Hard-Fork Signaling - (File: `ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs`)

---

### Summary

`applyHelper` in the Shelley ledger increments `shelleyAfterVoting` for every block whose slot is at or after the voting deadline, without an upper-bound cutoff at `votingDeadline + stabilityWindow`. The intended design (Iteration 4, documented in `civic_time.md`) requires counting only blocks that fall inside the one-stability-window interval immediately following the voting deadline. Using the wrong slot range — the full post-deadline tail of the epoch instead of the bounded stability window — means the hard-fork readiness gate can fire even when Chain Growth is violated inside the critical window, allowing a premature era transition based on a governance outcome that is not yet rollback-safe.

---

### Finding Description

`applyHelper` maintains `shelleyAfterVoting`, a counter used by `shelleyTransition` to decide whether to signal a hard fork to the Hard Fork Combinator (HFC):

```haskell
-- applyHelper, Ledger.hs lines 717-721
shelleyAfterVoting =
    (if blockSlot blk >= votingDeadline then succ else id) $
      shelleyAfterVoting tickedShelleyLedgerTransition
```

`votingDeadline` is `startOfNextEpoch - 2 * swindow` (line 745). The gate in `shelleyTransition` fires when:

```haskell
-- ShelleyHFC.hs line 224
guard $ shelleyAfterVoting >= fromIntegral k
```

The intended semantics, per Iteration 4 of the HFC design, is to count only blocks in the **stability window immediately after the voting deadline** — i.e., blocks with slot in `[votingDeadline, votingDeadline + swindow)`. This bounded window is what Chain Growth guarantees will contain at least `k` blocks, making the governance outcome rollback-safe. The current code has no upper bound: it counts every block from `votingDeadline` to the end of the epoch, including blocks in `[votingDeadline + swindow, startOfNextEpoch)` that lie outside the critical window.

This is explicitly acknowledged as a bug in the project's own documentation:

> *(TODO this is today's intended behavior, but a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window.)*

The analog to the external report is exact: the external hook checks `block.timestamp` (the current moment) instead of the `expiry` parameter (the intended deadline). Here, the code checks `blockSlot blk >= votingDeadline` (unbounded post-deadline range) instead of `blockSlot blk >= votingDeadline && blockSlot blk < votingDeadline + swindow` (the bounded stability-window range that the security argument actually covers).

---

### Impact Explanation

When Chain Growth is violated inside `[votingDeadline, votingDeadline + swindow)` — meaning fewer than `k` blocks appear in that window — but the total count across the full post-deadline tail `[votingDeadline, startOfNextEpoch)` reaches `k`, the node incorrectly concludes the governance outcome is rollback-safe and signals a hard-fork transition to the HFC. Because the stability window did not contain `k` blocks, the Praos security argument does not guarantee the governance outcome is immutable. A sufficiently deep rollback could revert the governance vote, leaving the node committed to an era transition that the honest chain has abandoned. This breaks the cross-era consensus invariant that the HFC transition point must be determined only from a ledger state that is at least `k` blocks past the voting deadline **within the stability window**.

Impact category: **High — Hard-fork, era transition, or ledger-view mismatch that breaks cross-era consensus or ledger invariants for production Cardano nodes.**

---

### Likelihood Explanation

Triggering the divergence requires two simultaneous conditions:

1. A legitimate on-chain governance proposal (submitted by genesis key delegates / SPOs) that would advance the major protocol version.
2. A Chain Growth violation specifically inside `[votingDeadline, votingDeadline + swindow)` — i.e., an adversary with enough stake to suppress block production in that window — while still allowing `k` blocks to appear in the broader `[votingDeadline, startOfNextEpoch)` interval.

This is a low-likelihood scenario in normal operation, but it is a reachable code path on any private testnet or adversarially controlled network where an operator controls a significant fraction of stake. The bug is self-documented and present in all current production nodes, meaning all nodes share the same incorrect behavior and would diverge identically — masking the bug on mainnet but leaving the invariant violated.

---

### Recommendation

Add an upper-bound check so that only blocks within the stability window after the voting deadline are counted:

```haskell
-- Intended: count only blocks in [votingDeadline, votingDeadline + swindow)
shelleyAfterVoting =
    ( if blockSlot blk >= votingDeadline
         && blockSlot blk < addSlots swindow votingDeadline
      then succ
      else id
    ) $
      shelleyAfterVoting tickedShelleyLedgerTransition
```

This aligns the implementation with the Iteration 4 design described in `civic_time.md` and ensures the hard-fork gate fires only when Chain Growth inside the critical window is satisfied.

---

### Proof of Concept

**Root cause — wrong range in `applyHelper`:** [1](#0-0) 

**`votingDeadline` definition (no upper bound is enforced):** [2](#0-1) 

**Hard-fork gate that consumes the counter:** [3](#0-2) 

**Self-acknowledged bug in the design documentation (Iteration 4):** [4](#0-3) 

**`ShelleyTransitionInfo` docstring explaining the intended k-block guarantee:** [5](#0-4)

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

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Ledger.hs (L717-721)
```haskell
                    { shelleyAfterVoting =
                        -- We count the number of blocks that have been applied after the
                        -- voting deadline has passed.
                        (if blockSlot blk >= votingDeadline then succ else id) $
                          shelleyAfterVoting tickedShelleyLedgerTransition
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

**File:** docs/website/contents/references/miscellaneous/civic_time.md (L201-205)
```markdown
**{Iteration 4} (latest)**.
In order to satisfy the DespiteChainGrowthViolation requirement, today's HFC inlcudes a radical rule.

  - Silently ignore the on-chain governance --- ie the HFC continues with the current era _despite the on-chain governance outcome having signaled the transition to the next era_ --- if the stability window after the voting deadline contains less than k+1 blocks (ie violates Chain Growth).
    (TODO this is today's intended behavior, but a bug is counting all blocks after the voting deadline instead of only those in the subsequent stability window.)
```
