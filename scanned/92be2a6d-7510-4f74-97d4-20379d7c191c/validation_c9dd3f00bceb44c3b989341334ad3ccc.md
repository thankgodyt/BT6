### Title
Inverted Success/Failure Condition in `submit_transfer_to_btc_connector_callback` Permanently Locks Fee Tokens — (`File: near/omni-bridge/src/btc.rs`)

### Summary
In `submit_transfer_to_btc_connector_callback`, the branch condition that decides whether to pay the relayer's fee or re-queue the transfer is inverted. On every **successful** NEAR → BTC/UTXO outbound transfer the fee tokens are never disbursed and remain permanently locked inside the bridge contract. On every **failed** transfer the fee is incorrectly paid out to the relayer.

### Finding Description

`submit_transfer_to_utxo_chain_connector` removes the pending transfer, then calls `ft_transfer_call` on the BTC token contract, sending only the net amount (total minus fee) to the UTXO connector: [1](#0-0) [2](#0-1) 

The fee tokens are **not** forwarded to the connector; they remain in the bridge contract. The callback is then responsible for disbursing them: [3](#0-2) 

Under the NEP-141 standard, `ft_transfer_call` returns the amount the receiver is **refunding** to the sender:
- `result.0 == 0` → connector accepted all tokens → **transfer succeeded**
- `result.0 > 0` → connector is refunding tokens → **transfer failed**

The condition `matches!(call_result, Ok(result) if result.0 > 0)` therefore fires on **failure**, not success. The two branches are swapped:

| Actual outcome | Condition fires? | Action taken | Correct action |
|---|---|---|---|
| Success (`result.0 == 0`) | **No** → `else` | Re-adds transfer to `pending_transfers` | Send fee to relayer |
| Failure (`result.0 > 0`) | **Yes** | Calls `send_fee_internal` | Re-add transfer |

On success, `send_fee_internal` is never called, so the fee tokens accumulate in the bridge with no disbursement path. The `else` branch re-inserts the transfer into `pending_transfers` via `add_transfer_message`, creating a stale entry for a transfer whose tokens have already left the bridge. [4](#0-3) 

The `send_fee_internal` function that would have disbursed the fee: [5](#0-4) 

### Impact Explanation

Every successful NEAR → Bitcoin/Zcash outbound transfer where `fee.fee > 0` results in the fee tokens being permanently locked inside the bridge contract. The `locked_tokens` accounting is also decremented inside `send_fee_internal` via `unlock_tokens_if_needed`, which is never called on the success path, leaving the accounting inconsistent. The stale re-inserted `pending_transfers` entry cannot be re-submitted successfully because the underlying tokens have already been sent to the UTXO connector.

This is permanent freezing of bridged funds (fee tokens) across Bitcoin and Zcash flows, matching the critical impact scope.

### Likelihood Explanation

The bug is triggered on **every** successful UTXO outbound transfer with a non-zero fee. Any trusted relayer calling `submit_transfer_to_utxo_chain_connector` on a pending BTC/Zcash transfer triggers it automatically. No special attacker action is required beyond normal bridge operation.

### Recommendation

Invert the condition in `submit_transfer_to_btc_connector_callback`:

```rust
// CORRECT: result.0 == 0 means the connector used all tokens (success)
if matches!(call_result, Ok(result) if result.0 == 0) {
    let token_fee = transfer_msg.fee.fee.0;
    self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
} else {
    // Failure: re-queue the transfer
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

### Proof of Concept

1. A user initiates a NEAR → BTC transfer with `fee = 1000` satoshi-equivalent tokens and `amount = 10000`.
2. A trusted relayer calls `submit_transfer_to_utxo_chain_connector`. The bridge removes the pending transfer and calls `ft_transfer_call` on the BTC token contract with `amount = 9000` (fee deducted). The 1000 fee tokens remain in the bridge.
3. The BTC connector successfully processes the withdrawal and returns `U128(0)` (used all 9000 tokens).
4. `submit_transfer_to_btc_connector_callback` receives `Ok(U128(0))`. The condition `result.0 > 0` is **false**, so the `else` branch executes: the transfer is re-added to `pending_transfers`.
5. `send_fee_internal` is never called. The 1000 fee tokens remain locked in the bridge contract indefinitely.
6. The relayer receives no fee. The stale pending entry cannot be re-submitted (tokens are gone). The only recovery is a DAO-level `transfer_token_as_dao` call. [6](#0-5)

### Citations

**File:** near/omni-bridge/src/btc.rs (L25-126)
```rust
impl Contract {
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
        let transfer = self.get_transfer_message_storage(transfer_id);

        let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
        let amount = U128(transfer.message.amount.0 - transfer.message.fee.fee.0);

        if let Some(btc_address) = transfer.message.recipient.get_utxo_address() {
            if let TokenReceiverMessage::Withdraw {
                target_btc_address,
                input: _,
                output: _,
                max_gas_fee,
            } = message
            {
                require!(
                    btc_address == target_btc_address,
                    BridgeError::IncorrectTargetUtxoAddress.as_ref()
                );

                let max_gas_fee_msg = DestinationChainMsg::from_json(&transfer.message.msg)
                    .and_then(|s| s.max_gas_fee());

                if let Some(max_gas_fee_msg) = max_gas_fee_msg {
                    require!(
                        max_gas_fee.expect("max_gas_fee is missing") == max_gas_fee_msg,
                        "Invalid max gas fee"
                    );
                }
            } else {
                env::panic_str("Invalid message type");
            }
        } else {
            env::panic_str("Invalid destination chain");
        }

        if let Some(fee) = &fee {
            require!(
                &transfer.message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let chain_kind = transfer.message.get_destination_chain();
        let btc_account_id = self.get_utxo_chain_token(chain_kind);
        require!(
            self.get_token_id(&transfer.message.token) == btc_account_id,
            BridgeError::NativeTokenRequiredForChain.as_ref()
        );

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

**File:** near/omni-bridge/src/lib.rs (L2650-2702)
```rust
    fn send_fee_internal(
        &mut self,
        transfer_message: &TransferMessage,
        fee_recipient: AccountId,
        token_fee: u128,
    ) -> PromiseOrValue<()> {
        if transfer_message.fee.native_fee.0 != 0 {
            let origin_chain = transfer_message.origin_transfer_id.as_ref().map_or_else(
                || transfer_message.get_origin_chain(),
                |origin_transfer_id| origin_transfer_id.origin_chain,
            );

            if origin_chain.is_utxo_chain() {
                env::panic_str(BridgeError::NativeFeeForUtxoChain.to_string().as_str())
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        env::log_str(
            &OmniBridgeEvent::ClaimFeeEvent {
                transfer_message: transfer_message.clone(),
            }
            .to_log_string(),
        );

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
        } else {
            PromiseOrValue::Value(())
        }
    }
```
