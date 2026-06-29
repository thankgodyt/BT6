### Title
Relayer Funds Permanently Lost When `send_tokens` Fails in `utxo_fin_transfer_fast` — (File: `near/omni-bridge/src/lib.rs`)

### Summary
In `utxo_fin_transfer_fast`, the fast-transfer state is irrevocably committed (record removed or marked finalised) before `send_tokens` is called with `.detach()`. If the token transfer fails, the relayer's pre-financed tokens are permanently lost with no recovery path. The developer has explicitly acknowledged this gap with a `// TODO: check how to deal with failed send_tokens` comment at the call site.

### Finding Description

`utxo_fin_transfer_fast` is invoked from `utxo_fin_transfer` when a UTXO-chain finalization arrives for a transfer that a relayer already fast-transferred: [1](#0-0) 

```rust
if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
    // TODO: check how to deal with failed send_tokens
    return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
}
```

Inside `utxo_fin_transfer_fast`, the fast-transfer record is permanently mutated **before** the token transfer is attempted: [2](#0-1) 

```rust
let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
    self.remove_fast_transfer(&fast_transfer.id());   // ← state permanently deleted
    fast_transfer.amount
} else {
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← state permanently finalised
    U128(fast_transfer.amount_without_fee().near_expect(BridgeError::InvalidFee))
};

self.send_tokens(
    fast_transfer.token_id.clone(),
    fast_transfer_status.relayer,
    amount,
    "",
)
.detach();   // ← fire-and-forget, no failure callback
```

`.detach()` schedules the token transfer as a separate NEAR receipt with **no callback**. If that receipt fails (token contract panic, missing storage registration, gas exhaustion, etc.), the state changes above are already committed and cannot be rolled back. The fast-transfer record is gone or permanently finalised, so the repayment cannot be retried.

An identical pattern exists in `process_fin_transfer_to_other_chain` for EVM/Solana fast transfers: [3](#0-2) 

```rust
if let Some(relayer) = recipient {
    self.send_tokens(token, relayer, U128(...), "").detach(); // ← no callback
    self.mark_fast_transfer_as_finalised(&fast_transfer.id()); // ← committed regardless
}
```

### Impact Explanation

When a relayer performs a fast transfer, they send their own tokens to the bridge to pre-finance the user. The bridge owes the relayer a repayment when the original UTXO transfer is finalized. If `send_tokens` fails in `utxo_fin_transfer_fast`, the tokens remain locked inside the bridge contract while the fast-transfer record is already removed or finalised. There is no admin recovery function, no retry mechanism, and no event that signals the failure. The relayer's bridged funds are permanently frozen — a direct loss of bridged assets matching the Critical impact scope.

### Likelihood Explanation

Medium. Realistic failure modes for the detached `send_tokens` call include:

- The relayer's account lacks a storage registration for the specific token (NEP-141 requires `storage_deposit` before receiving tokens via `ft_transfer`).
- The token contract panics on `mint` or `ft_transfer` due to an edge case or upgrade.
- Gas exhaustion inside the token contract when the bridge is called with near-minimum gas.

None of these require attacker privilege; they can arise from ordinary operational conditions.

### Recommendation

Replace the `.detach()` call in `utxo_fin_transfer_fast` (and the analogous site in `process_fin_transfer_to_other_chain`) with a proper callback. On failure, the callback should restore the fast-transfer record (re-insert or un-finalise it) so the repayment can be retried. Alternatively, introduce a permissioned recovery function that allows the DAO or the relayer to reclaim tokens when the initial repayment receipt failed.

### Proof of Concept

1. Relayer calls `ft_on_transfer` with a `FastFinTransfer` message for a UTXO-chain transfer, sending their own tokens to the bridge to pre-finance the user.
2. The UTXO connector later calls `ft_on_transfer` with a `UtxoFinTransfer` message to finalize the original transfer.
3. `utxo_fin_transfer` detects the existing fast-transfer record and calls `utxo_fin_transfer_fast`.
4. `utxo_fin_transfer_fast` calls `remove_fast_transfer` (or `mark_fast_transfer_as_finalised`), permanently committing the state change.
5. `send_tokens(...).detach()` is scheduled. The relayer's account has no storage registration for the token, so the `ft_transfer` receipt panics and is silently dropped.
6. The fast-transfer record is already gone; no retry is possible.
7. The relayer's pre-financed tokens remain locked in the bridge contract with no recovery path. [4](#0-3) [1](#0-0) [3](#0-2)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L2483-2486)
```rust
        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
        }
```

**File:** near/omni-bridge/src/lib.rs (L2518-2561)
```rust
    fn utxo_fin_transfer_fast(
        &mut self,
        fast_transfer: FastTransfer,
        fast_transfer_status: FastTransferStatus,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            !fast_transfer_status.finalised,
            BridgeError::FastTransferAlreadyFinalised.as_ref()
        );

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

        env::log_str(
            &OmniBridgeEvent::UtxoTransferEvent {
                token_id: fast_transfer.token_id,
                amount,
                utxo_transfer_message: utxo_fin_transfer_msg,
                new_transfer_id: None,
            }
            .to_log_string(),
        );

        PromiseOrPromiseIndexOrValue::Value(U128(0))
    }
```
