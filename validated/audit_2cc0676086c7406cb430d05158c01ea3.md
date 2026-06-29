### Title
Detached `send_tokens` Promise in `utxo_fin_transfer_fast` Causes Permanent Relayer Fund Loss on Failure — (`near/omni-bridge/src/lib.rs`)

---

### Summary

In `utxo_fin_transfer_fast`, for non-NEAR destination transfers, the contract calls `mark_fast_transfer_as_finalised` (committing `finalised=true` to persistent state) and then calls `send_tokens(...).detach()`. Because the promise is detached, any failure of the token transfer is silently ignored. The fast transfer entry is permanently locked as finalised with no recovery path, and the relayer permanently loses the tokens they advanced.

---

### Finding Description

The vulnerable path is in `utxo_fin_transfer_fast`:

```
// near/omni-bridge/src/lib.rs:2529-2548
let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());
    fast_transfer.amount
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // <-- state committed
    U128(fast_transfer.amount_without_fee().near_expect(...))
};

self.send_tokens(
    fast_transfer.token_id.clone(),
    fast_transfer_status.relayer,
    amount,
    "",
)
.detach(); // <-- result never checked
``` [1](#0-0) 

`mark_fast_transfer_as_finalised` writes `finalised=true` into the `fast_transfers` map: [2](#0-1) 

In NEAR, state mutations in the current execution frame are committed atomically when the transaction completes. A `.detach()`-ed promise runs in a separate receipt; if it fails, the parent transaction's state is **not** rolled back. The guard at the top of `utxo_fin_transfer_fast` then permanently blocks any retry: [3](#0-2) 

The developers themselves flagged this at the call site with an unresolved TODO: [4](#0-3) 

**Conditions under which `send_tokens` fails:**

- The relayer's NEAR account has no storage deposit registered on the token contract (NEP-141 requires `storage_deposit` before `ft_transfer` or `mint` can succeed).
- The token contract panics for any reason (e.g., paused, upgraded, or buggy).

For a BTC→EVM fast transfer, `fast_fin_transfer_to_other_chain` burns/locks the relayer's tokens at fast-transfer time: [5](#0-4) 

When `utxo_fin_transfer_fast` runs and `send_tokens` fails, those burned/locked tokens are irrecoverable — the fast transfer entry is finalised, the UTXO transfer is processed, and no admin or user function exists to reset the state or retry the send.

The same structural flaw exists in `process_fin_transfer_to_other_chain` (lines 2028–2040), where `send_tokens(...).detach()` is also used without a failure callback before `mark_fast_transfer_as_finalised`. [6](#0-5) 

---

### Impact Explanation

A relayer who correctly executed a fast transfer for a BTC→EVM (or any non-NEAR destination) transfer permanently loses the tokens they advanced if the reimbursement `send_tokens` call fails. The fast transfer is marked finalised, the UTXO transfer is processed, and there is no recovery path. This constitutes permanent loss of relayer funds — a Critical impact under "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds."

---

### Likelihood Explanation

The failure condition (relayer not registered for the token) is realistic: a new relayer, a token with non-standard storage requirements, or a token contract that is paused or upgraded between fast-transfer and finalization can all trigger this. The TODO comment at line 2484 confirms the developers are aware the failure case is unhandled.

---

### Recommendation

Replace `.detach()` with a chained callback that checks the promise result and, on failure, resets `finalised` back to `false` (or removes the entry) so the send can be retried. Pattern to follow: `utxo_fin_transfer_to_near_callback` / `resolve_utxo_fin_transfer` already implement this correctly for the NEAR-destination path by chaining a `resolve_utxo_fin_transfer` callback that handles failure. [7](#0-6) 

---

### Proof of Concept

1. Deploy a mock NEP-141 token contract that panics on `ft_transfer`.
2. Register the token in the bridge; configure a UTXO chain connector.
3. Relayer calls `fast_fin_transfer` for a BTC→EVM transfer — tokens are burned/locked, fast transfer entry recorded with `finalised=false`.
4. UTXO connector calls `ft_on_transfer` with `UtxoFinTransfer` message → `utxo_fin_transfer` → `utxo_fin_transfer_fast`.
5. `mark_fast_transfer_as_finalised` sets `finalised=true` (committed to state).
6. `send_tokens(...).detach()` fires; the mock token panics; the receipt fails silently.
7. Assert: `fast_transfer_status.finalised == true`, relayer token balance unchanged, no retry possible (next call panics with `FastTransferAlreadyFinalised`).

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

**File:** near/omni-bridge/src/lib.rs (L994-1011)
```rust
        self.send_tokens(
            token_id.clone(),
            recipient,
            amount,
            &utxo_fin_transfer_msg.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_UTXO_FIN_TRANSFER_GAS)
                .resolve_utxo_fin_transfer(
                    token_id,
                    amount,
                    utxo_fin_transfer_msg,
                    origin_chain,
                    storage_owner,
                ),
        )
        .into()
```

**File:** near/omni-bridge/src/lib.rs (L2028-2041)
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
        } else {
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
