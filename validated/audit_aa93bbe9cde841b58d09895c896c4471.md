### Title
Inverted Success/Failure Condition in BTC Connector Callback Enables Double-Spending of Bridged UTXO Funds - (File: near/omni-bridge/src/btc.rs)

### Summary

`submit_transfer_to_btc_connector_callback` uses an inverted condition to distinguish a successful BTC/Zcash withdrawal from a failed one. Under NEAR's NEP-141 `ft_transfer_call` semantics, `result.0 == 0` means the receiver consumed all tokens (success) and `result.0 > 0` means the receiver returned tokens (failure). The callback has these two branches swapped: it sends the fee on failure and re-inserts the transfer message on success, allowing a trusted relayer to re-submit the same transfer repeatedly and drain the bridge.

### Finding Description

In `submit_transfer_to_utxo_chain_connector`, the transfer message is removed from `pending_transfers` before the `ft_transfer_call` to the BTC connector is dispatched: [1](#0-0) 

The callback that handles the result is: [2](#0-1) 

Under NEP-141, `ft_transfer_call` resolves with the amount the receiver did **not** use:
- `result.0 == 0` → receiver consumed all tokens → **BTC withdrawal succeeded**
- `result.0 > 0` → receiver returned tokens → **BTC withdrawal failed**

The callback condition `if matches!(call_result, Ok(result) if result.0 > 0)` therefore fires on **failure**, yet it calls `send_fee_internal` (paying the fee recipient). The `else` branch fires on **success**, yet it calls `add_transfer_message` (re-inserting the transfer into `pending_transfers`). Both branches are inverted relative to their correct semantics.

The correct logic (mirroring `is_refund_required` used elsewhere in the codebase) is: [3](#0-2) 

### Impact Explanation

**Critical — double-spending of bridged UTXO funds.**

When the BTC connector successfully processes a withdrawal (`result.0 == 0`), the callback re-inserts the transfer message into `pending_transfers`. A trusted relayer can then call `submit_transfer_to_utxo_chain_connector` again with the same `transfer_id`, triggering a second BTC withdrawal for the same user deposit. This loop can be repeated until the bridge's BTC/Zcash token balance is exhausted, constituting a complete loss of all bridged UTXO-chain funds held by the bridge.

Additionally, when the BTC connector fails (`result.0 > 0`), the fee is incorrectly paid to the fee recipient even though no withdrawal occurred, and the transfer message is **not** re-inserted, permanently locking the user's funds with no recovery path.

### Likelihood Explanation

The entry point `submit_transfer_to_utxo_chain_connector` is gated by `#[trusted_relayer]`: [4](#0-3) 

A registered trusted relayer — an externally reachable actor explicitly listed in the audit objective as "custom relayer" — can exploit this without any additional privilege escalation. The BTC/Zcash withdrawal path is a live production flow, so any successful withdrawal automatically triggers the vulnerable callback.

### Recommendation

Swap the two branches so that the fee is sent on success (`result.0 == 0`) and the transfer is re-inserted on failure (`result.0 > 0`):

```rust
pub fn submit_transfer_to_btc_connector_callback(
    &mut self,
    transfer_msg: TransferMessage,
    transfer_owner: AccountId,
    fee_recipient: AccountId,
    #[callback_result] call_result: &Result<U128, PromiseError>,
) -> PromiseOrValue<()> {
-   if matches!(call_result, Ok(result) if result.0 > 0) {
+   if matches!(call_result, Ok(result) if result.0 == 0) {
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

### Proof of Concept

1. A user initiates a NEAR→BTC transfer; a `TransferMessage` is stored in `pending_transfers` with `transfer_id = T`.
2. A trusted relayer calls `submit_transfer_to_utxo_chain_connector(T, msg, fee_recipient, fee)`.
3. The bridge removes `T` from `pending_transfers` and calls `ft_transfer_call` to the BTC connector.
4. The BTC connector successfully processes the withdrawal and returns `U128(0)`.
5. `submit_transfer_to_btc_connector_callback` is invoked with `result.0 == 0`. The condition `result.0 > 0` is **false**, so the `else` branch executes: `add_transfer_message` re-inserts `T` into `pending_transfers`.
6. The relayer calls `submit_transfer_to_utxo_chain_connector(T, msg, fee_recipient, fee)` again.
7. Steps 3–6 repeat, draining the bridge's BTC token balance with each iteration. [2](#0-1)

### Citations

**File:** near/omni-bridge/src/btc.rs (L26-35)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn submit_transfer_to_utxo_chain_connector(
        &mut self,
        transfer_id: TransferId,
        msg: String,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
```

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

**File:** near/omni-bridge/src/lib.rs (L1784-1804)
```rust
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
            match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
                Ok(value) => {
                    if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                        // Normal case: refund if the used token amount is zero
                        // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                        amount.0 == 0
                    } else {
                        // Unexpected case: don't refund
                        false
                    }
                }
                // Unexpected case: don't refund
                Err(_) => false,
            }
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
    }
```
