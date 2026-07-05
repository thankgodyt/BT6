### Title
Missing Return Value from `applyAlonzoBasedTx` Silently Suppresses `IsValid` Flag Correction, Preventing Peer Disconnection — (`File: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Eras.hs`)

---

### Summary

`applyAlonzoBasedTx` silently corrects a transaction's `IsValid` flag when a peer submits a transaction whose claimed two-phase-validation outcome is wrong, but returns no value indicating that this correction occurred. The caller therefore cannot detect the branch was taken and cannot disconnect from the offending peer. This is the direct Haskell analog of the ERC-20 `approve()` unchecked-return-value class: a critical operation produces a distinguishing outcome that is structurally invisible to its caller.

---

### Finding Description

`applyAlonzoBasedTx` is the `applyShelleyBasedTx` implementation for Alonzo, Babbage, Conway, and Dijkstra eras. [1](#0-0) 

When `wti = DoNotIntervene`, the function first forces `IsValid = True` on the incoming transaction and attempts to apply it. If the ledger rejects it with a `ValidationTagMismatch` predicate failure (i.e., the peer claimed the scripts pass but they actually fail, or vice versa), the `handler` silently re-applies the transaction with the corrected flag `IsValid = False`: [2](#0-1) 

The function's return type is:

```haskell
Except (SL.ApplyTxError era)
  ( SL.LedgerState era
  , SL.Validated (Core.Tx TopTx era)
  )
```

Both the "applied as submitted" path and the "silently corrected flag" path return the same type with no distinguishing tag. The codebase itself acknowledges this gap with an explicit TODO: [3](#0-2) 

> `-- TODO 'applyTx' et al needs to include a return value indicating`
> `-- whether we took this branch; it's a reason to disconnect from`
> `-- the peer who sent us the incorrect flag (ie Issue #3276)`

Because no such return value exists, every caller — including the mempool update path — receives a successful `(mempoolState', vtx)` pair with no way to distinguish a legitimately valid transaction from one whose `IsValid` flag was silently overridden.

The mempool update path that calls `applyShelleyBasedTx` (via `validateNewTransaction`) processes the result as a plain success: [4](#0-3) 

There is no post-call inspection for whether the flag was corrected, and no peer-disconnection logic is triggered.

---

### Impact Explanation

**Medium.** This is a miniprotocol-level flaw that materially weakens transaction authorization for Alonzo-and-later eras (Alonzo, Babbage, Conway, Dijkstra — all active Cardano eras). Specifically:

- A peer submitting a transaction via the local-tx-submission or node-to-node mempool path can deliberately set an incorrect `IsValid` flag.
- The node silently corrects the flag, includes the transaction in the mempool, and returns success to the caller.
- Because the return value carries no signal that the correction occurred, the peer is never disconnected.
- The peer can repeat this indefinitely across all four affected eras without any protocol-level consequence.

The transaction itself is applied correctly (collateral is taken when `IsValid = False`), so there is no double-spend or ledger-state corruption. However, the authorization invariant — that a peer who lies about script validity is disconnected — is permanently unenforceable until the return type is extended.

---

### Likelihood Explanation

**Medium.** Any unprivileged peer that can submit transactions (via the standard tx-submission mini-protocol) can trigger this path by setting `IsValid = True` on a transaction whose Plutus scripts fail. No special keys, stake, or operator access are required. The affected eras cover all post-Alonzo Cardano mainnet activity.

---

### Recommendation

Extend the return type of `applyShelleyBasedTx` (and `applyAlonzoBasedTx`) to carry a flag indicating whether the `IsValid` correction branch was taken, for example:

```haskell
data ApplyTxOutcome = AppliedAsIs | AppliedWithCorrectedIsValid

Except (SL.ApplyTxError era)
  ( SL.LedgerState era
  , SL.Validated (Core.Tx TopTx era)
  , ApplyTxOutcome          -- NEW
  )
```

Callers in the mempool update path should inspect this outcome and, when `AppliedWithCorrectedIsValid` is returned, trigger peer disconnection via the existing `InvalidBlockPunishment` / peer-punishment infrastructure. This resolves the acknowledged Issue #3276.

---

### Proof of Concept

1. Construct a Babbage-era transaction `tx` with a Plutus script that fails at evaluation, but set `tx.isValid = True`.
2. Submit `tx` to a node via the local-tx-submission mini-protocol (`wti = DoNotIntervene`).
3. Inside `applyAlonzoBasedTx`, `defaultApplyShelleyBasedTx` raises `ValidationTagMismatch`; `isIncorrectClaimedFlag` returns `True`; the handler re-applies with `IsValid = False`.
4. The mempool accepts the transaction (collateral path). The caller receives `Right (vtx, df)` — indistinguishable from a clean submission.
5. The peer is not disconnected. Steps 1–4 can be repeated without limit. [5](#0-4)

### Citations

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Eras.hs (L192-215)
```haskell
instance ShelleyBasedEra AlonzoEra where
  applyShelleyBasedTx = applyAlonzoBasedTx

  getConwayEraGovDict = defaultGetConwayEraGovDict

  mkEraMkMempoolApplyTxError _prx = Nothing

instance ShelleyBasedEra BabbageEra where
  applyShelleyBasedTx = applyAlonzoBasedTx

  getConwayEraGovDict = defaultGetConwayEraGovDict

  mkEraMkMempoolApplyTxError _prx = Nothing

instance ShelleyBasedEra ConwayEra where
  applyShelleyBasedTx = applyAlonzoBasedTx

  getConwayEraGovDict _ = Just ConwayEraGovDict

  mkEraMkMempoolApplyTxError _prx =
    Just $ \txt -> ConwayApplyTxError (NE.singleton (Conway.ConwayMempoolFailure txt))

instance ShelleyBasedEra DijkstraEra where
  applyShelleyBasedTx = applyAlonzoBasedTx
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Eras.hs (L240-273)
```haskell
applyAlonzoBasedTx globals ledgerEnv mempoolState wti tx = do
  (mempoolState', vtx) <-
    (`catchError` handler) $
      defaultApplyShelleyBasedTx
        globals
        ledgerEnv
        mempoolState
        wti
        intervenedTx
  pure (mempoolState', vtx)
 where
  intervenedTx = case wti of
    DoNotIntervene -> tx & Core.isValidTxL .~ Alonzo.IsValid True
    Intervene -> tx

  handler e = case (wti, e) of
    (DoNotIntervene, err)
      | isIncorrectClaimedFlag (Proxy @era) err ->
          -- rectify the flag and include the transaction
          --
          -- This either lets the ledger punish the script author for sending
          -- a bad script or else prevents our peer's buggy script validator
          -- from preventing inclusion of a valid script.
          --
          -- TODO 'applyTx' et al needs to include a return value indicating
          -- whether we took this branch; it's a reason to disconnect from
          -- the peer who sent us the incorrect flag (ie Issue #3276)
          defaultApplyShelleyBasedTx
            globals
            ledgerEnv
            mempoolState
            wti
            (tx & Core.isValidTxL .~ Alonzo.IsValid False)
    _ -> throwError e
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Update.hs (L395-416)
```haskell
              case validateNewTransaction cfg wti tx txsz values st is of
                (Left err, _) ->
                  Processed $ \_dur ->
                    TransactionProcessingResult
                      Nothing
                      (MempoolTxRejected tx err)
                      ( TraceMempoolRejectedTx
                          tx
                          err
                          MempoolRejectedByLedger
                          (isMempoolSize is)
                      )
                (Right (vtx, df), is') ->
                  Processed $ \dur ->
                    TransactionProcessingResult
                      (Just (is' dur))
                      (MempoolTxAdded vtx df)
                      ( TraceMempoolAddedTx
                          vtx
                          (isMempoolSize is)
                          (isMempoolSize (is' dur))
                      )
```
