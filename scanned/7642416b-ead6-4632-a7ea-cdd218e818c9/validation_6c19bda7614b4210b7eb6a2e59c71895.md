### Title
Inverted Success/Failure Check in `submit_transfer_to_btc_connector_callback` Causes User Funds to Be Permanently Stuck and Fee Mis-Accounting - (File: near/omni-bridge/src/btc.rs)

---

### Summary

`submit_transfer_to_btc_connector_callback` in `near/omni-bridge/src/btc.rs` uses an inverted condition to distinguish BTC withdrawal success from failure. The callback sends the relayer fee when the BTC connector **returns tokens** (failure) and restores the transfer when the connector **consumes all tokens** (success). This is the exact opposite of the correct behavior, causing user funds to be permanently locked in the bridge on any BTC withdrawal failure, and ghost transfer records to be re-inserted on success.

---

### Finding Description

In `submit_transfer_to_utxo_chain_connector`, the transfer message is removed from storage before the `ft_transfer_call` is dispatched to the BTC connector: [1](#0-0) 

The callback that follows is: [2](#0-1) 

Under NEAR's NEP-141 standard, `ft_transfer_call` returns the amount of tokens **not consumed** by the receiver (i.e., refunded). Therefore:

- `Ok(result) if result.0 == 0` → all tokens consumed → **BTC withdrawal succeeded**
- `Ok(result) if result.0 > 0` → tokens returned → **BTC withdrawal failed**

The condition `matches!(call_result, Ok(result) if result.0 > 0)` matches the **failure** case, yet the code sends the fee to the relayer in this branch. The **success** case (`result.0 == 0`) falls into the `else` branch and re-inserts the transfer message into storage — even though the BTC withdrawal already completed and the tokens were already forwarded to the connector.

This is directly analogous to M-22's pattern of using the wrong address/token in intermediate steps of a multi-step token flow, here manifesting as inverted callback logic.

Compare with the correct pattern used elsewhere in the same contract (`fin_transfer_send_tokens_callback`), where the success path sends the fee and the failure path reverts state: [3](#0-2) 

---

### Impact Explanation

**On BTC withdrawal failure** (`result.0 > 0`, tokens returned to bridge):

1. The bridge receives back `amount - fee` tokens from the connector.
2. `send_fee_internal` is called, transferring `fee` tokens to the relayer — even though the withdrawal failed.
3. The transfer record is **not restored**. The remaining `amount - fee` tokens sit in the bridge with no associated transfer record.
4. The user permanently loses their funds with no recourse.

**On BTC withdrawal success** (`result.0 == 0`, all tokens consumed):

1. The transfer record is re-inserted into storage via `add_transfer_message`.
2. The fee is **not** paid to the relayer.
3. A ghost transfer record now exists for a transfer whose tokens have already been forwarded. A relayer can attempt to call `submit_transfer_to_utxo_chain_connector` again; the `ft_transfer_call` will fail because the bridge no longer holds those tokens, but the ghost record persists and wastes storage.

The primary critical impact is **permanent loss of user funds** whenever a BTC withdrawal fails for any reason (invalid UTXO, network congestion, connector-side rejection). [4](#0-3) 

---

### Likelihood Explanation

BTC withdrawals can fail for entirely legitimate, non-adversarial reasons: invalid or already-spent UTXOs, connector-side gas fee limits exceeded, network congestion, or connector contract bugs. Any such failure triggers the inverted callback. The user who initiated the transfer has no ability to prevent or recover from this. The code path is live in production for all BTC/Zcash UTXO chain transfers.

---

### Recommendation

Invert the condition so that the fee is sent on success (`result.0 == 0`) and the transfer is restored on failure:

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

---

### Proof of Concept

1. User holds wrapped BTC on NEAR and initiates a BTC withdrawal via `ft_transfer_call` to the bridge, creating a `TransferMessage` with `amount = 1_000_000` and `fee = 10_000`.
2. A trusted relayer calls `submit_transfer_to_utxo_chain_connector`. The bridge removes the transfer record and calls `ft_transfer_call(connector, 990_000, ...)`.
3. The BTC connector's `ft_on_transfer` fails (e.g., UTXO already spent) and returns `990_000` (all tokens refunded).
4. `submit_transfer_to_btc_connector_callback` is invoked with `Ok(U128(990_000))`.
5. The condition `result.0 > 0` is true → `send_fee_internal` is called, transferring `10_000` tokens to the relayer.
6. The transfer record is **not** restored. The `990_000` returned tokens sit in the bridge with no associated record.
7. The user has lost `1_000_000` tokens permanently. [5](#0-4)

### Citations

**File:** near/omni-bridge/src/btc.rs (L84-126)
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

**File:** near/omni-bridge/src/lib.rs (L1719-1746)
```rust
        } else {
            // Send fee to the fee recipient
            if transfer_message.fee.fee.0 > 0 {
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
            }

            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }

            env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
        }
```
