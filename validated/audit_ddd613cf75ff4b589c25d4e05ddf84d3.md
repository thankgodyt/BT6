### Title
GDD Genesis Window Computed from Stale Immutable Ledger State Silently Disables Density Disconnection During Era Transitions — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Genesis/Governor.hs`)

---

### Summary

In `evaluateGDD`, the genesis window size `msgen` is derived from the **immutable** ledger state rather than the current selection's ledger state. During era transitions, when the LoE tip advances into a new era whose parameters are not yet covered by the hard-fork summary of the immutable ledger state, `runQuery` returns `Left PastHorizonException`, `eitherToMaybe` silently converts this to `Nothing`, and the entire `whenJust msgen` block is skipped. The result is that the Genesis Density Disconnection (GDD) mechanism is completely disabled: no peers are evaluated for density, no low-density peers are disconnected, and the LoE anchor cannot advance.

---

### Finding Description

`evaluateGDD` in `Governor.hs` computes the genesis window for the slot immediately after the LoE tip:

```haskell
msgen = eitherToMaybe $ runQuery qry summary
 where
  slot    = succWithOrigin $ AF.headSlot loeFrag
  qry     = qryFromExpr $ slotToGenesisWindow slot
  summary = hardForkSummary
              (configLedger cfg)
              (ledgerState immutableLedgerSt)   -- ← wrong state
```

The code comment at lines 251–259 explicitly acknowledges the defect:

> *"one could also use the ledger state at the tip of our selection here (in which case this should never return 'Nothing'), but this is subtle and maybe not desirable. In any case, the immutable ledger state will also /eventually/ catch up to the LoE tip, so @msgen@ won't be 'Nothing' forever."*

The hard-fork summary built from the immutable ledger state covers only slots within the safe zone of the last confirmed era transition. `hard_won_wisdom.md` confirms: *"the query will fail if and only if its argument is beyond the HFC's current lower bound for the next unknown era end."* When the LoE tip is in a new era whose transition block is still in the volatile suffix (i.e., fewer than k blocks deep), the immutable ledger state has not yet confirmed that transition, so `slotToGenesisWindow` for the LoE tip slot throws `PastHorizonException`.

`eitherToMaybe` silently converts this failure to `Nothing`. The guard at line 261:

```haskell
whenJust msgen $ \sgen -> do
  ...
  whenJust (NE.nonEmpty losingPeers) $ \losingPeersNE -> do
    for_ losingPeersNE $ \peer -> killActions Map.! peer
```

is then entirely skipped. `densityDisconnect` is never called, no peers are killed, and `evaluateGDD` returns the unchanged `loeFrag` — the LoE anchor does not advance.

This is the direct analog of the original report: a security-enforcement function reads from the wrong location (`immutableLedgerSt` instead of the current selection's ledger state), causing the entire enforcement mechanism to produce a vacuous no-op.

---

### Impact Explanation

GDD is the Genesis chain-selection safety mechanism that disconnects peers whose candidate chains are too sparse to be the honest chain, thereby unblocking the LoE and allowing the node's selection to advance. When GDD is silently disabled:

1. Low-density adversarial peers are not disconnected.
2. The LoE anchor remains at the intersection of all candidate fragments.
3. The node's selection cannot advance more than k blocks beyond that intersection.
4. The honest chain tip — which may be arbitrarily far ahead — cannot be adopted.

The node is forced to prefer a shorter, less-secure prefix of the honest chain over the full honest chain, violating the intended Genesis security assumption that GDD will always disconnect sparser competing chains and allow the selection to converge on the densest (honest) chain.

**Impact class:** High — chain-selection / genesis bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

Era transitions occur on a fixed schedule in the Cardano network (every major protocol upgrade). During the window in which the era-transition block is in the volatile suffix (up to k ≈ 2160 blocks), any peer that serves headers crossing the era boundary can push the LoE tip into the new era. Because the immutable ledger state has not yet confirmed the transition, `msgen = Nothing` and GDD is disabled for the entire duration of that window. No special privileges, keys, or stake are required; any connected peer serving a chain that crosses the era boundary suffices.

---

### Recommendation

Replace `ledgerState immutableLedgerSt` with the ledger state at the tip of the current selection, as the in-code comment already suggests. The current selection's ledger state is always at least as fresh as the LoE tip, so `hardForkSummary` built from it will always cover the LoE tip slot and `msgen` will never be `Nothing`.

Concretely, add the current selection's ledger state to `GDDStateView` (alongside `gddCtxImmutableLedgerSt`) and use it in `evaluateGDD`:

```haskell
-- In GDDStateView, add:
, gddCtxCurrentLedgerSt :: ExtLedgerState blk EmptyMK

-- In evaluateGDD, change:
summary = hardForkSummary (configLedger cfg) (ledgerState gddCtxCurrentLedgerSt)
```

`getGDDStateView` already reads `ChainDB.getCurrentChainWithTime`; a companion `ChainDB.getCurrentLedger` call in the same STM transaction would supply the needed state consistently.

---

### Proof of Concept

1. Node is syncing; immutable tip is at slot S in era N. The era N→N+1 transition block is at slot S+δ (δ < k blocks deep, so still volatile).
2. An adversary (or any peer) serves headers that cross the era boundary, up to some slot S′ in era N+1. The honest peer also serves headers into era N+1.
3. `sharedCandidatePrefix` computes `loeFrag` with its head at some slot S″ ≥ S+δ in era N+1.
4. `slot = succWithOrigin (AF.headSlot loeFrag)` is a slot in era N+1.
5. `hardForkSummary (configLedger cfg) (ledgerState immutableLedgerSt)` is built from the immutable ledger state at slot S (era N). The era N+1 transition is not yet confirmed, so the summary's safe zone does not cover slot S″+1.
6. `runQuery (qryFromExpr (slotToGenesisWindow (S″+1))) summary` returns `Left PastHorizonException` (confirmed by `Qry.hs` lines 385–389: `EGenesisWindow` fails when the slot is not within any era's bounds in the summary).
7. `msgen = Nothing`. The `whenJust msgen` block at line 261 is skipped entirely.
8. The adversary's low-density chain is not disconnected. The LoE anchor stays at S″. The node cannot advance its selection beyond S″ + k, while the honest chain tip may be far beyond that. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Genesis/Governor.hs (L136-148)
```haskell
  getGDDStateView :: STM m (GDDStateView m blk peer)
  getGDDStateView = do
    curChain <- ChainDB.getCurrentChainWithTime chainDb
    immutableLedgerSt <- ChainDB.getImmutableLedger chainDb
    handles <- getHandles
    states <- traverse (readTVar . cschState) handles
    pure
      GDDStateView
        { gddCtxCurChain = curChain
        , gddCtxImmutableLedgerSt = immutableLedgerSt
        , gddCtxKillActions = Map.map cschGDDKill handles
        , gddCtxStates = states
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Genesis/Governor.hs (L238-261)
```haskell
      msgen :: Maybe GenesisWindow
      -- This could also use 'runWithCachedSummary' if deemed desirable.
      msgen = eitherToMaybe $ runQuery qry summary
       where
        -- We use the Genesis window for the first slot /after/ the common
        -- intersection. In particular, when the intersection is the last
        -- slot of an era, we will use the Genesis window of the next era,
        -- as all slots in the Genesis window reside in that next era.
        slot = succWithOrigin $ AF.headSlot loeFrag
        qry = qryFromExpr $ slotToGenesisWindow slot
        summary =
          hardForkSummary
            (configLedger cfg)
            -- Due to the cross-chain lemma (Property 17.3 in the Consensus
            -- report) one could also use the ledger state at the tip of our
            -- selection here (in which case this should never return
            -- 'Nothing'), but this is subtle and maybe not desirable.
            --
            -- In any case, the immutable ledger state will also
            -- /eventually/ catch up to the LoE tip, so @msgen@ won't be
            -- 'Nothing' forever.
            (ledgerState immutableLedgerSt)

  whenJust msgen $ \sgen -> do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Genesis/Governor.hs (L281-285)
```haskell
    whenJust (NE.nonEmpty losingPeers) $ \losingPeersNE -> do
      for_ losingPeersNE $ \peer -> killActions Map.! peer
      traceWith tracer $ TraceGDDDisconnected losingPeersNE

  pure loeFrag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L385-389)
```haskell
  go (EGenesisWindow expr) = do
    s <- go expr
    guard $ s >= boundSlot eraStart
    guardEnd $ \end -> s < boundSlot end
    return eraGenesisWin
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/Qry.hs (L408-418)
```haskell
data PastHorizonException = PastHorizon
  { pastHorizonCallStack :: CallStack
  -- ^ Callstack to the call to 'runQuery'
  , pastHorizonExpression :: Some ClosedExpr
  -- ^ The 'Expr' we tried to evaluate
  , pastHorizonSummary :: [EraSummary]
  -- ^ The 'EraSummary's that we tried to evaluate the 'Expr' against
  }

deriving instance Show PastHorizonException
instance Exception PastHorizonException
```
