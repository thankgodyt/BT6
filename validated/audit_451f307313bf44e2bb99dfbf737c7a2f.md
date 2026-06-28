### Title
Inverted NEP-141 Callback Condition in `submit_transfer_to_btc_connector_callback` Enables Stale Re-insertion and Potential Double-Spend — (`near/omni-bridge/src/btc.rs`)

---

### Summary

The callback condition `matches!(call_result, Ok(result) if result.0 > 0)` in `submit_transfer_to_btc_connector_callback` is inverted relative to NEP-141 `ft_transfer_call` semantics. Under NEP-141, `ft_transfer_call` resolves to the number of tokens **unused** (refunded). A return value of `0` means the receiver accepted **all** tokens — i.e., success. A return value `> 0` means some tokens were returned — i.e., partial or full rejection.

The code treats `result.0 > 0` as success (sends fee) and `result.0 == 0` as failure (re-inserts the transfer into `pending_transfers`). This is exactly backwards.

---

### Finding Description

In `submit_transfer_to_utxo_chain_connector`, the bridge:
1. Removes transfer `T` from `pending_transfers`
2. Calls `ft_transfer_call` on the nBTC token, forwarding `amount` to the BTC connector [1](#0-0) 

In the callback: [2](#0-1) 

When the BTC connector's `ft_on_transfer` correctly accepts all tokens and returns `0`, `ft_transfer_call` resolves to `Ok(U128(0))`. The condition `result.0 > 0` is **false**, so execution falls into the `else` branch, which calls `add_transfer_message` and re-inserts `T` back into `pending_transfers`. [3](#0-2) 

`add_transfer_message` panics only if the key already exists — but since `T` was removed before the `ft_transfer_call`, the re-insertion succeeds silently. [4](#0-3) 

---

### Impact Explanation

After the callback re-inserts `T`, a trusted relayer observing `T` still in `pending_transfers` will naturally retry `submit_transfer_to_utxo_chain_connector` for the same `transfer_id`. This is normal relayer behavior — the relayer has no way to distinguish a re-inserted-on-success entry from a genuinely failed one.

On the second call:
- The bridge removes `T` again and calls `ft_transfer_call` again for the same `amount`
- The bridge's nBTC balance at this point is `B - amount` (from the first successful transfer). If other users' pending transfers hold sufficient nBTC (i.e., `B ≥ 2 × amount`), the second `ft_transfer_call` succeeds
- The BTC connector receives `amount` nBTC a second time and initiates a second MPC signing request for the same withdrawal
- The result is a double-spend: the user's BTC recipient address receives two on-chain BTC outputs for a single bridged transfer, funded by draining other users' escrowed nBTC

The `#[trusted_relayer]` guard limits callers, but does not prevent the bug from manifesting in normal operation — no malicious intent is required. [5](#0-4) 

---

### Likelihood Explanation

The condition fires on every successful BTC withdrawal (the normal case). Any relayer running standard retry logic against `pending_transfers` will trigger the second submission. The only practical brake is whether the bridge holds enough nBTC from other users to fund the second transfer — which is likely in any live deployment with concurrent users.

---

### Recommendation

Invert the condition to match NEP-141 semantics:

```rust
// Correct: result.0 == 0 means all tokens were accepted (success)
if matches!(call_result, Ok(result) if result.0 == 0) {
    let token_fee = transfer_msg.fee.fee.0;
    self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
} else {
    // Connector returned tokens or call failed — re-insert transfer
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

Additionally, consider adding a `finalised_utxo_transfers`-style idempotence guard keyed on `transfer_id` before the `ft_transfer_call` to prevent any re-submission regardless of callback outcome.

---

### Proof of Concept

1. Deploy the bridge with a mock BTC connector whose `ft_on_transfer` returns `U128(0)` (all tokens accepted — correct NEP-141 behavior).
2. User initiates a BTC withdrawal; transfer `T` enters `pending_transfers`.
3. Trusted relayer calls `submit_transfer_to_utxo_chain_connector(T, ...)`.
4. Bridge removes `T`, sends `amount` nBTC to connector; connector returns `0`.
5. Callback sees `result.0 == 0` → `else` branch → `add_transfer_message` re-inserts `T`.
6. Relayer queries `get_transfer_message(T)` — it exists — and calls `submit_transfer_to_utxo_chain_connector(T, ...)` again.
7. Bridge removes `T` again, sends `amount` nBTC again (from other users' escrowed balance).
8. Assert: connector received `2 × amount` nBTC; MPC signing was requested twice for the same transfer.

### Citations

**File:** near/omni-bridge/src/btc.rs (L23-29)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn submit_transfer_to_utxo_chain_connector(
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

**File:** near/omni-bridge/src/lib.rs (L2180-2192)
```rust
    fn add_transfer_message(
        &mut self,
        transfer_message: TransferMessage,
        message_owner: AccountId,
    ) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.insert_raw_transfer(transfer_message, message_owner,)
                .is_none(),
            BridgeError::KeyExists.as_ref()
        );
        env::storage_byte_cost().saturating_mul((env::storage_usage() - storage_usage).into())
    }
```
