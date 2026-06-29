Now I have all the code needed to analyze this. Let me verify the NEP-141 semantics and the `send_fee_internal` behavior in context.

I now have all the information needed for a complete analysis. The code is clear.

---

### Title
Inverted Success/Failure Branches in `submit_transfer_to_btc_connector_callback` Enable Double-Spending of BTC/Zcash Funds and Permanent User Token Loss — (`near/omni-bridge/src/btc.rs`)

### Summary

The callback `submit_transfer_to_btc_connector_callback` has its success and failure branches swapped relative to NEP-141 `ft_transfer_call` semantics. When the BTC/Zcash connector **accepts** the transfer (returns `0` from `ft_on_transfer`), the bridge re-inserts the transfer into `pending_transfers` instead of paying the relayer fee. When the connector **rejects** the transfer (returns `> 0`), the bridge pays the relayer fee instead of re-inserting the transfer. This allows a trusted relayer to double-spend bridged BTC/Zcash funds by repeatedly submitting the same transfer, and causes permanent loss of user funds on any legitimate connector rejection.

### Finding Description

In `near/omni-bridge/src/btc.rs`, `submit_transfer_to_utxo_chain_connector` removes the transfer from state at line 84, then calls `ft_transfer_call` on the nBTC/nZEC token to the connector. The callback receives the NEP-141 return value:

```rust
// near/omni-bridge/src/btc.rs lines 111-125
if matches!(call_result, Ok(result) if result.0 > 0) {
    // result.0 > 0 = connector REFUNDED tokens = FAILURE
    let token_fee = transfer_msg.fee.fee.0;
    self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)  // ← pays fee on FAILURE
} else {
    // result.0 == 0 = connector KEPT tokens = SUCCESS
    // Also covers Err(PromiseError) = connector panicked = FAILURE
    self.add_transfer_message(transfer_msg, transfer_owner.clone()); // ← re-inserts on SUCCESS
    PromiseOrValue::Value(())
}
```

Under NEP-141, `ft_on_transfer` returns the amount to **refund** to the sender:
- Returns `0` → connector kept all tokens → **SUCCESS** (BTC withdrawal will proceed)
- Returns `> 0` → connector is refunding tokens → **FAILURE** (BTC withdrawal rejected)

The branches are exactly backwards.

**Double-spend path (connector returns 0 = success):**

1. User A has a pending transfer of `amount` nBTC to a BTC address (fee = `f`)
2. Trusted relayer calls `submit_transfer_to_utxo_chain_connector` with User A's `transfer_id`
3. Bridge removes User A's transfer from `pending_transfers` (line 84) and calls `ft_transfer_call` sending `amount - f` nBTC to the connector
4. Connector's `ft_on_transfer` returns `0` (success — it accepted the tokens and will process the BTC withdrawal)
5. Callback: `result.0 == 0` → else branch → `add_transfer_message` **re-inserts** User A's transfer into `pending_transfers`
6. Bridge state: User A's transfer is back in `pending_transfers`, but `amount - f` nBTC are already with the connector (and a BTC UTXO is being prepared)
7. Trusted relayer calls `submit_transfer_to_utxo_chain_connector` again with the same `transfer_id`
8. Bridge removes User A's transfer again and sends another `amount - f` nBTC to the connector — this time drawn from **other users' locked tokens**
9. Connector accepts again, callback re-inserts again
10. Cycle repeats until the bridge's nBTC balance is drained

**Token loss path (connector returns > 0 = failure):**

1. Connector rejects the transfer, refunding `amount - f` nBTC back to the bridge (NEP-141 handles the refund automatically)
2. Callback: `result.0 > 0` → if branch → `send_fee_internal` pays `f` nBTC to the relayer
3. Transfer is **never re-inserted** — it is permanently gone from `pending_transfers`
4. User A's `amount - f` nBTC sit in the bridge's balance with no associated transfer record; they are unrecoverable

### Impact Explanation

**Double-spending (Critical):** A trusted relayer can drain the bridge's entire nBTC/nZEC balance by repeatedly submitting the same transfer after each successful connector acceptance re-inserts it. Each iteration steals `amount - fee` tokens from other users' pending transfers. The bridge's `locked_tokens` accounting is also corrupted because `lock_tokens_if_needed` is not called on re-insertion in the callback path.

**Permanent fund loss (Critical):** On any legitimate connector rejection, the user's full transfer amount is permanently frozen in the bridge contract. The relayer collects the fee despite no BTC withdrawal occurring. The user has no recourse — the transfer ID no longer exists in `pending_transfers` and cannot be resubmitted.

### Likelihood Explanation

The double-spend path triggers on every **normal successful** connector call (the connector returns `0` when it accepts). This is the expected happy path. Any trusted relayer — even one acting in good faith — will observe the transfer re-appearing in `pending_transfers` after a successful submission and can exploit it. The token-loss path triggers on every connector rejection, which is also a normal operational scenario (e.g., invalid UTXO inputs, fee too low, connector paused).

The `#[trusted_relayer]` guard restricts the entry point, but trusted relayers are an expected operational role, not an admin/operator. The bug manifests in normal operation without any key compromise.

### Recommendation

Swap the branches in `submit_transfer_to_btc_connector_callback`:

```rust
pub fn submit_transfer_to_btc_connector_callback(
    &mut self,
    transfer_msg: TransferMessage,
    transfer_owner: AccountId,
    fee_recipient: AccountId,
    #[callback_result] call_result: &Result<U128, PromiseError>,
) -> PromiseOrValue<()> {
    // result.0 == 0 means connector kept all tokens = SUCCESS → pay fee
    if matches!(call_result, Ok(result) if result.0 == 0) {
        let token_fee = transfer_msg.fee.fee.0;
        self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
    } else {
        // result.0 > 0 (refund) or Err (panic) = FAILURE → re-insert transfer
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

Deploy a mock connector whose `ft_on_transfer` always returns `0`. Call `submit_transfer_to_utxo_chain_connector` for a valid pending transfer. After the callback fires, query `get_transfer_message` with the same `transfer_id` — it will be present (re-inserted). Call `submit_transfer_to_utxo_chain_connector` a second time with the same `transfer_id`. The bridge will attempt a second `ft_transfer_call` to the connector, drawing from other users' locked nBTC. Assert that the bridge's nBTC balance decreased by `2 × (amount - fee)` while only one user's transfer was originally pending.

For the token-loss path: deploy a mock connector whose `ft_on_transfer` returns the full amount (rejection). After the callback fires, assert that `get_transfer_message` returns `TransferNotExist` for the transfer ID, and that the relayer's nBTC balance increased by `fee` despite no BTC withdrawal occurring.

---

**Root cause references:** [1](#0-0) 

The transfer removal before the async call: [2](#0-1) 

`add_transfer_message` requires the key to not exist (enforced by `is_none()` check), confirming re-insertion succeeds after removal: [3](#0-2) 

`send_fee_internal` pays the fee via `ft_transfer` (nBTC is not a deployed token) or `mint`, and calls `unlock_tokens_if_needed` — both are wrong on connector failure: [4](#0-3)

### Citations

**File:** near/omni-bridge/src/btc.rs (L84-100)
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
```

**File:** near/omni-bridge/src/btc.rs (L111-125)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L2180-2191)
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
```

**File:** near/omni-bridge/src/lib.rs (L2684-2698)
```rust
        self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);

        if token_fee > 0 {
            if self.is_deployed_token(&token) {
                ext_token::ext(token)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient, U128(token_fee), None)
                    .into()
            } else {
                ext_token::ext(token)
                    .with_static_gas(FT_TRANSFER_GAS)
                    .with_attached_deposit(ONE_YOCTO)
                    .ft_transfer(fee_recipient, U128(token_fee), None)
                    .into()
            }
```
