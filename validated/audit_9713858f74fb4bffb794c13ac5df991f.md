### Title
Detached `send_tokens` Promise After Irrevocable `mark_fast_transfer_as_finalised` Causes Permanent Relayer Fund Loss — (`near/omni-bridge/src/lib.rs`)

---

### Summary

In `utxo_fin_transfer_fast`, when the destination chain is not NEAR, the contract permanently marks the fast transfer as finalised **before** dispatching the relayer reimbursement as a detached (fire-and-forget) promise. If that promise fails, the fast transfer record is irrecoverably finalised and the relayer has no recourse to recover their advance payment. The developers themselves flagged this exact gap with a `TODO` comment at the call site.

---

### Finding Description

`utxo_fin_transfer_fast` handles the case where a UTXO-origin transfer (e.g. BTC→EVM) arrives at finalization and a fast transfer was already executed by a relayer.

For the non-NEAR destination branch:

```
mark_fast_transfer_as_finalised(&fast_transfer.id());   // line 2533 — state written
...
self.send_tokens(...).detach();                          // line 2542-2548 — result ignored
``` [1](#0-0) 

`mark_fast_transfer_as_finalised` sets `finalised = true` and persists it to storage immediately. [2](#0-1) 

`.detach()` schedules the cross-contract `ft_transfer` / `mint` promise but **discards its result**. NEAR's execution model commits all state mutations from the current call frame regardless of what detached child promises do. If the detached promise fails (token contract panics, recipient not registered, insufficient gas allocated to the child, etc.), the `finalised = true` state persists and the relayer has no way to retry — the guard at line 2524–2527 will reject any future attempt with `FastTransferAlreadyFinalised`. [3](#0-2) 

The same pattern exists in `process_fin_transfer_to_other_chain` for the non-UTXO path: [4](#0-3) 

Critically, the developers themselves acknowledged this is unresolved. At the call site in `utxo_fin_transfer`: [5](#0-4) 

```rust
// TODO: check how to deal with failed send_tokens
return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
```

This is an explicit in-code admission that the failure path has no resolution.

---

### Impact Explanation

The relayer advanced their own tokens to the recipient during `fast_fin_transfer_to_other_chain` (those tokens were burned/locked from the relayer's account at line 932). The only recovery mechanism is the reimbursement in `utxo_fin_transfer_fast`. If that reimbursement promise fails silently, the relayer's advance is permanently lost — the tokens are burned and the fast transfer record is finalised, closing every retry path. This is a permanent, unrecoverable loss of bridged funds belonging to the relayer. [6](#0-5) 

---

### Likelihood Explanation

Concrete failure triggers for the detached `send_tokens`:

1. **Recipient not registered with the token contract** — for native (non-deployed) tokens, `send_tokens` calls `ft_transfer`, which panics if the recipient has no storage deposit. A relayer who burned tokens from their account was registered as a *sender*, but if their storage registration was subsequently removed (e.g. via `storage_unregister`) before finalization arrives, `ft_transfer` fails silently.
2. **Token contract upgrade or panic** — any panic in the token contract's `ft_transfer` or `mint` is swallowed by `.detach()`.
3. **Gas starvation of the child promise** — `send_tokens` computes remaining gas dynamically; if the parent call consumed most of the prepaid gas before reaching `send_tokens`, the child promise may receive insufficient gas and fail.

The TODO comment confirms the developers have not resolved this and consider it an open risk.

---

### Recommendation

Replace the fire-and-forget pattern with a chained callback that rolls back `finalised` (or re-queues the reimbursement) on failure:

```rust
self.send_tokens(...)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(RESOLVE_UTXO_FAST_TRANSFER_GAS)
            .resolve_utxo_fast_transfer_reimbursement(
                &fast_transfer.id(),
                fast_transfer_status.relayer.clone(),
                amount,
            ),
    )
```

In the callback, check `env::promise_result(0)`. On failure, either revert `finalised` to `false` (allowing a retry) or emit a recoverable pending-reimbursement record that DAO/admin can settle. Remove the `TODO` comment only after this is implemented.

The same fix is needed in `process_fin_transfer_to_other_chain` at lines 2029–2040.

---

### Proof of Concept

1. Deploy a mock NEP-141 token that panics on `ft_transfer` when called with a specific recipient.
2. Register the mock token in the bridge and configure a UTXO chain connector.
3. Have a trusted relayer call `fast_fin_transfer` for a BTC→EVM transfer; the relayer's tokens are burned (line 932).
4. Trigger `ft_on_transfer` from the UTXO connector with a `UtxoFinTransfer` message matching the same transfer ID.
5. `utxo_fin_transfer` detects the existing fast transfer status and calls `utxo_fin_transfer_fast`.
6. `mark_fast_transfer_as_finalised` sets `finalised = true` (line 2533).
7. `send_tokens(...).detach()` dispatches the mock token's `ft_transfer`, which panics; the detached promise fails silently.
8. **Assert**: `get_fast_transfer_status` returns `finalised = true`; relayer token balance is unchanged (reimbursement never arrived).
9. **Assert**: Any retry of the finalization call fails with `FastTransferAlreadyFinalised`.

The relayer's advance is permanently lost with no protocol-level recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L928-938)
```rust
        let amount_without_fee = fast_transfer
            .amount_without_fee()
            .near_expect(BridgeError::InvalidFee);

        self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());

        self.lock_tokens_if_needed(
            fast_transfer.get_destination_chain(),
            &fast_transfer.token_id,
            amount_without_fee,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2028-2040)
```rust
        if let Some(relayer) = recipient {
            self.send_tokens(
                token,
                relayer,
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
                "",
            )
            .detach();
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
```

**File:** near/omni-bridge/src/lib.rs (L2270-2277)
```rust
    fn mark_fast_transfer_as_finalised(&mut self, fast_transfer_id: &FastTransferId) {
        let mut status = self
            .get_fast_transfer_status(fast_transfer_id)
            .near_expect(BridgeError::FastTransferNotFound);
        status.finalised = true;
        self.fast_transfers
            .insert(fast_transfer_id, &FastTransferStatusStorage::V0(status));
    }
```

**File:** near/omni-bridge/src/lib.rs (L2483-2486)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
        }
```

**File:** near/omni-bridge/src/lib.rs (L2524-2527)
```rust
        require!(
            !fast_transfer_status.finalised,
            BridgeError::FastTransferAlreadyFinalised.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2529-2548)
```rust
        let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
            self.remove_fast_transfer(&fast_transfer.id());
            fast_transfer.amount
        } else {
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
            // With transfers to other chain the fee will be claimed after finalization on the destination chain
            U128(
                fast_transfer
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            )
        };

        self.send_tokens(
            fast_transfer.token_id.clone(),
            fast_transfer_status.relayer,
            amount,
            "",
        )
        .detach();
```
