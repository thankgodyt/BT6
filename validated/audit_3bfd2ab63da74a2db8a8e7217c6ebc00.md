### Title
Missing Era-Mismatch Check in `interpretQueryIfCurrentLookup` / `interpretQueryIfCurrentTraverse` Silently Returns Wrong-Era Ledger Data - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger/Query.hs`)

---

### Summary

`interpretQueryIfCurrentLookup` and `interpretQueryIfCurrentTraverse` — the Hard Fork Combinator's handlers for `QFLookupTables` and `QFTraverseTables` ledger queries — omit the era-mismatch guard that their `QFNoTables` counterpart (`interpretQueryIfCurrent`) correctly enforces. When a client sends a `QueryIfCurrent (QZ qry)` (first-era query) while the node's ledger state is in a later era, the handler silently answers the query with the wrong era's data instead of returning `Left (MismatchEraInfo …)`. This is the direct analog of the ERC721 `receive()` forwarding omission: a catch-all dispatch arm absorbs the call without delegating to the correct handler.

---

### Finding Description

`interpretQueryIfCurrent` (the `QFNoTables` path) correctly enforces era alignment:

```haskell
-- Query.hs lines 380-387
go (c :* _) (QZ qry) (Z (Flip st)) =          -- era match → answer
    Right $ answerPureBlockQuery c qry st
go _ (QZ qry) (S st) =                         -- era mismatch → error
    Left $ MismatchEraInfo $ ML (queryInfo qry) …
go _ (QS qry) (Z (Flip st)) =                  -- era mismatch → error
    Left $ MismatchEraInfo $ MR (hardForkQueryInfo qry) …
```

`interpretQueryIfCurrentLookup` (the `QFLookupTables` path) drops the ledger-state era check entirely for the `QZ` case:

```haskell
-- Query.hs lines 407-412
go (idx :* _) (c :* _) (QZ qry) _ =           -- ← wildcard: ledger era ignored
    Right <$> answerBlockQueryHFLookup idx c qry forker
go (_ :* idx) (_ :* cs) (QS qry) (S st) =
    first shiftMismatch <$> go idx cs qry st
go _ _ (QS qry) (Z (Flip st)) =               -- only this mismatch arm exists
    pure $ Left $ MismatchEraInfo $ MR …
```

The identical omission appears in `interpretQueryIfCurrentTraverse` at line 432:

```haskell
go (idx :* _) (c :* _) (QZ qry) _ =           -- ← same wildcard
    Right <$> answerBlockQueryHFTraverse idx c qry forker
```

Both functions read the current ledger state from the forker at the top of the function:

```haskell
-- Query.hs lines 396-398
interpretQueryIfCurrentLookup cfg q forker = do
  st <- distribExtLedgerState <$> atomically (roforkerGetLedgerState forker)
  go indices cfg q st
```

but then the `QZ` arm discards `st` entirely via the `_` wildcard.

**Concrete execution path for Cardano (Shelley-era query against a Conway-era node):**

A client sends `QueryIfCurrent (QS (QZ q))` — a Shelley-era `QFLookupTables` query (e.g., a UTxO lookup). The node is in Conway era, so `st = S (S (S (S (S (S (S (Z …)))))))`. The recursion peels one `S` from both query and state:

```
go … (QS (QZ q)) (S (S (S (S (S (S (S (Z …)))))))) 
  → go … (QZ q) (S (S (S (S (S (S (Z …)))))))   ← hits the wildcard arm
  → Right <$> answerBlockQueryHFLookup (IS IZ) shelleyCfg q forker
```

`answerBlockQueryHFLookup` is dispatched through `answerCardanoQueryHF` in `QueryHF.hs` (lines 63–76), which calls `answerShelleyLookupQueries` with the Shelley-era config but the Conway-era forker. Because Shelley-based eras share the same `CanonicalTxIn` key space (all use `BigEndianTxIn`), the lookup succeeds against the Conway UTxO tables and returns Conway-era `TxOut` values wrapped in Shelley-era types — wrong data returned as `Right result` with no error signal.

The missing arm that should exist (mirroring `interpretQueryIfCurrent`) is:

```haskell
go _ _ (QZ qry) (S st) =
    pure $ Left $ MismatchEraInfo $ ML (queryInfo qry) …
```

---

### Impact Explanation

An unprivileged client querying the node's Local State Query miniprotocol with a `QueryIfCurrent` for an earlier era (e.g., Shelley) while the node is in a later era (e.g., Conway) receives `Right <wrong-era-data>` instead of `Left (MismatchEraInfo …)`. The client has no way to distinguish this from a legitimate successful response. Consequences include:

- A wallet or dApp performing UTxO lookups receives stale or misinterpreted UTxO entries, potentially leading to double-spend attempts or incorrect balance displays.
- The client suppresses its own era-upgrade logic because it believes the query succeeded in the current era.
- The node's state-query authorization contract — that `QueryIfCurrent` only succeeds when the ledger is actually in the queried era — is silently violated for all `QFLookupTables` and `QFTraverseTables` queries.

This fits the **Medium** allowed impact: *"Public node API or miniprotocol flaw that exposes sensitive consensus state or materially weakens … state-query authorization without relying on DoS."*

---

### Likelihood Explanation

The Local State Query miniprotocol is reachable by any unprivileged client connecting to the node's local socket (e.g., cardano-wallet, cardano-db-sync, dApps). Any client that retains a Shelley-era query type and issues it against a post-Shelley node triggers the bug. This is a realistic scenario during era transitions or when clients lag behind the node's current era. No special privileges, keys, or stake are required.

---

### Recommendation

Add the missing era-mismatch guard to both `interpretQueryIfCurrentLookup` and `interpretQueryIfCurrentTraverse`, mirroring `interpretQueryIfCurrent`:

```haskell
-- interpretQueryIfCurrentLookup
go (idx :* _) (c :* _) (QZ qry) (Z _) =
    Right <$> answerBlockQueryHFLookup idx c qry forker
go _ _ (QZ qry) (S st) =
    pure $ Left $ MismatchEraInfo $
      ML (queryInfo qry) (hcmap proxySingle (ledgerInfo . unFlip) st)

-- interpretQueryIfCurrentTraverse (same pattern)
go (idx :* _) (c :* _) (QZ qry) (Z _) =
    Right <$> answerBlockQueryHFTraverse idx c qry forker
go _ _ (QZ qry) (S st) =
    pure $ Left $ MismatchEraInfo $
      ML (queryInfo qry) (hcmap proxySingle (ledgerInfo . unFlip) st)
```

---

### Proof of Concept

**Root cause — missing guard in `interpretQueryIfCurrentLookup`:** [1](#0-0) 

**Root cause — same missing guard in `interpretQueryIfCurrentTraverse`:** [2](#0-1) 

**Correct reference implementation in `interpretQueryIfCurrent` (the `QFNoTables` path) that properly checks era alignment:** [3](#0-2) 

**Entry point — `answerBlockQueryLookup` and `answerBlockQueryTraverse` dispatch to the buggy functions:** [4](#0-3) 

**`answerBlockQueryHelper` reads the current ledger state and passes it to the buggy `go` function:** [5](#0-4) 

**Cardano's `answerBlockQueryHFLookup` dispatches to `answerShelleyLookupQueries` using the era index and the current-era forker — confirming the wrong-era data path:** [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger/Query.hs (L243-246)
```haskell
  answerBlockQueryLookup cfg (QueryIfCurrent q) =
    answerBlockQueryHelper interpretQueryIfCurrentLookup cfg q
  answerBlockQueryTraverse cfg (QueryIfCurrent q) =
    answerBlockQueryHelper interpretQueryIfCurrentTraverse cfg q
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger/Query.hs (L278-290)
```haskell
answerBlockQueryHelper
  f
  (ExtLedgerCfg cfg)
  qry
  forker = do
    hardForkState <-
      hardForkLedgerStatePerEra . ledgerState <$> atomically (roforkerGetLedgerState forker)
    let ei = State.epochInfoLedger lcfg hardForkState
        cfgs = hmap ExtLedgerCfg $ distribTopLevelConfig ei cfg
    f cfgs qry forker
   where
    lcfg = configLedger cfg

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger/Query.hs (L380-387)
```haskell
  go (c :* _) (QZ qry) (Z (Flip st)) =
    Right $ answerPureBlockQuery c qry st
  go (_ :* cs) (QS qry) (S st) =
    first shiftMismatch $ go cs qry st
  go _ (QZ qry) (S st) =
    Left $ MismatchEraInfo $ ML (queryInfo qry) (hcmap proxySingle (ledgerInfo . unFlip) st)
  go _ (QS qry) (Z (Flip st)) =
    Left $ MismatchEraInfo $ MR (hardForkQueryInfo qry) (ledgerInfo st)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger/Query.hs (L407-412)
```haskell
  go (idx :* _) (c :* _) (QZ qry) _ =
    Right <$> answerBlockQueryHFLookup idx c qry forker
  go (_ :* idx) (_ :* cs) (QS qry) (S st) =
    first shiftMismatch <$> go idx cs qry st
  go _ _ (QS qry) (Z (Flip st)) =
    pure $ Left $ MismatchEraInfo $ MR (hardForkQueryInfo qry) (ledgerInfo st)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger/Query.hs (L432-437)
```haskell
  go (idx :* _) (c :* _) (QZ qry) _ =
    Right <$> answerBlockQueryHFTraverse idx c qry forker
  go (_ :* idx) (_ :* cs) (QS qry) (S st) =
    first shiftMismatch <$> go idx cs qry st
  go _ _ (QS qry) (Z (Flip st)) =
    pure $ Left $ MismatchEraInfo $ MR (hardForkQueryInfo qry) (ledgerInfo st)
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/QueryHF.hs (L88-104)
```haskell
instance CardanoHardForkConstraints c => BlockSupportsHFLedgerQuery (CardanoEras c) where
  answerBlockQueryHFLookup =
    answerCardanoQueryHF
      ( \idx ->
          answerShelleyLookupQueries
            (injectLedgerTables idx)
            (ejectHardForkTxOut idx)
            (coerce . ejectCanonicalTxIn idx)
      )
  answerBlockQueryHFTraverse =
    answerCardanoQueryHF
      ( \idx ->
          answerShelleyTraversingQueries
            (ejectHardForkTxOut idx)
            (coerce . ejectCanonicalTxIn idx)
            (queryLedgerGetTraversingFilter idx)
      )
```
