### Title
Inverted Success/Failure Condition in `submit_transfer_to_btc_connector_callback` Permanently Locks User nBTC Funds - (File: `near/omni-bridge/src/btc.rs`)

### Summary

In `submit_transfer_to_btc_connector_callback`, the NEP-141 `ft_transfer_call` result is interpreted with inverted logic. When the UTXO connector rejects a transfer (returns `result.0 > 0`, meaning tokens were refunded), the code incorrectly treats this as success and sends the fee. When the connector accepts the transfer (returns `result.0 == 0`), the code incorrectly re-inserts the pending transfer. The failure path does not re-insert the `TransferMessage` into `pending_transfers`, permanently locking the user's nBTC in the bridge contract with no recovery path.

### Finding Description

`submit_transfer_to_utxo_chain_connector` removes the pending transfer from state before dispatching `ft_transfer_call` to the UTXO connector: [1](#0-0) 

The callback then decides whether to re-insert the transfer or send the fee: [2](#0-1) 

Under NEP-141, `ft_on_transfer` returns the amount to **refund** to the sender. A return value of `0` means the connector consumed all tokens (success); a return value `> 0` means the connector rejected some or all tokens (failure). The guard `result.0 > 0` therefore matches the **failure** case, yet the code sends the fee on that branch and re-inserts the transfer on the success branch — the exact opposite of correct behavior.

When the connector rejects the transfer:
1. `result.0 > 0` matches → `send_fee_internal` is called (fee paid for a failed transfer).
2. The `else` branch is skipped → `add_transfer_message` is **never called**.
3. The nBTC tokens are refunded by the token contract back to the bridge, but no `pending_transfers` entry exists.
4. There is no `cancel_transfer` or equivalent function to let the user reclaim tokens without a pending entry.

The user's nBTC is permanently locked inside the bridge contract.

### Impact Explanation

This is a permanent, irrecoverable loss of bridged funds. The user's nBTC tokens are held by the bridge contract with no on-chain mechanism to retrieve them. The fee recipient additionally receives an unearned fee. This matches the **Critical** impact class: escrow mis-accounting and permanent freezing of bridged funds.

### Likelihood Explanation

The UTXO connector can legitimately reject a transfer for many reasons: invalid UTXO inputs, insufficient gas fee, connector paused, or any internal validation failure. No malicious actor is required — a routine connector rejection during normal bridge operation triggers the bug. The trusted relayer acts in good faith; the loss is caused entirely by the inverted condition in the callback.

### Recommendation

Invert the condition so that `result.0 == 0` (all tokens consumed = success) triggers fee payment, and any other outcome (tokens refunded or promise error) re-inserts the transfer:

```rust
// Correct logic:
if matches!(call_result, Ok(result) if result.0 == 0) {
    // Success: connector accepted all tokens → pay fee
    let token_fee = transfer_msg.fee.fee.0;
    self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
} else {
    // Failure: connector rejected tokens → re-insert transfer for retry
    let required_storage_balance =
        self.add_transfer_message(transfer_msg, transfer_owner.clone());
    self.update_storage_balance(
        transfer_owner,
        required_storage_balance,
        NearToken::from_yoctonear(0),
    );
    PromiseOrValue::Value(())
}
```

Also consider increasing `SUBMIT_TRANSFER_TO_BTC_CONNECTOR_CALLBACK_GAS` beyond 5 TGas to ensure the re-insertion path has sufficient gas for storage operations.

### Proof of Concept

1. User initiates a NEAR→BTC transfer via `ft_transfer_call` → `init_transfer`. A `TransferMessage` is stored in `pending_transfers`.
2. Trusted relayer calls `submit_transfer_to_utxo_chain_connector(transfer_id, msg, ...)`.
3. `remove_transfer_message(transfer_id)` removes the entry from `pending_transfers` and refunds storage to the owner. [3](#0-2) 
4. `ft_transfer_call` sends nBTC to the connector. The connector's `ft_on_transfer` rejects the transfer and returns the full amount (e.g., invalid UTXO), so `call_result = Ok(U128(amount))` where `amount > 0`.
5. In the callback, `matches!(call_result, Ok(result) if result.0 > 0)` is `true`. [4](#0-3) 
6. `send_fee_internal` is called — fee is paid to the relayer for a failed transfer.
7. The `else` branch (re-insertion) is skipped. The `TransferMessage` is gone from `pending_transfers`.
8. The NEP-141 token contract refunds the nBTC back to the bridge contract, but no pending transfer entry exists.
9. The user's nBTC is permanently locked in the bridge with no recovery path.

### Citations

**File:** near/omni-bridge/src/btc.rs (L84-101)
```rust
        self.remove_transfer_message(transfer_id);

        let fee_recipient = fee_recipient.unwrap_or(env::predecessor_account_id());

        ext_token::ext(btc_account_id)
            .with_attached_deposit(ONE_YOCTO)
            .with_static_gas(FT_TRANSFER_CALL_GAS)
            .ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SUBMIT_TRANSFER_TO_BTC_CONNECTOR_CALLBACK_GAS)
                    .submit_transfer_to_btc_connector_callback(
                        transfer.message,
                        transfer.owner,
                        fee_recipient,
                    ),
            )
    }
```

**File:** near/omni-bridge/src/btc.rs (L103-126)
```rust
    #[private]
    pub fn submit_transfer_to_btc_connector_callback(
        &mut self,
        transfer_msg: TransferMessage,
        transfer_owner: AccountId,
        fee_recipient: AccountId,
        #[callback_result] call_result: &Result<U128, PromiseError>,
    ) -> PromiseOrValue<()> {
        if matches!(call_result, Ok(result) if result.0 > 0) {
            let token_fee = transfer_msg.fee.fee.0;
            self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
        } else {
            let required_storage_balance =
                self.add_transfer_message(transfer_msg, transfer_owner.clone());

            self.update_storage_balance(
                transfer_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            PromiseOrValue::Value(())
        }
    }
```
