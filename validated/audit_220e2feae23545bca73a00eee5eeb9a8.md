### Title
Undetected `ft_transfer` Failure in `fin_transfer_send_tokens_callback` Permanently Freezes Bridged Funds - (`near/omni-bridge/src/lib.rs`)

### Summary

When finalizing an inbound transfer to a NEAR recipient (`fin_transfer`), the bridge marks the transfer as finalized **before** sending tokens. If the subsequent `ft_transfer` to the recipient fails (e.g., due to a token-level blacklist or pause), the callback `fin_transfer_send_tokens_callback` does not detect the failure when `msg` is empty (`is_ft_transfer_call = false`). The transfer is permanently recorded as finalized and cannot be replayed, causing bridged funds to be permanently frozen inside the bridge contract.

### Finding Description

The `process_fin_transfer_to_near` function first calls `add_fin_transfer` to record the transfer as finalized, then calls `send_tokens` to deliver tokens to the recipient, and finally chains `fin_transfer_send_tokens_callback` as a `.then()` callback. [1](#0-0) 

Inside `send_tokens`, when the token is a non-deployed (native/locked) NEP-141 token and `msg` is empty, a plain `ft_transfer` is issued: [2](#0-1) 

The callback `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = !msg.is_empty()`. When `msg` is empty, `is_ft_transfer_call = false`: [3](#0-2) 

Inside the callback, `is_refund_required(false)` unconditionally returns `false`: [4](#0-3) 

This means the callback **always** takes the success path when `msg` is empty, regardless of whether the `ft_transfer` promise succeeded or failed. It emits `FinTransferEvent` and sends fees, but never reverts the finalization record or restores locked tokens: [5](#0-4) 

By contrast, when `msg` is non-empty (`ft_transfer_call` path), the callback correctly reads the promise result and can trigger a refund/revert: [6](#0-5) 

The `add_fin_transfer` call at the start of `process_fin_transfer_to_near` inserts the transfer ID into `finalised_transfers`, preventing any future replay attempt. Once the `ft_transfer` silently fails, the tokens are permanently stranded in the bridge with no recovery path. [7](#0-6) 

### Impact Explanation

Bridged funds (non-deployed NEP-141 tokens held in escrow by the bridge) are permanently frozen. The transfer is marked finalized so it cannot be re-submitted. The user loses their bridged assets with no recourse. This is a direct loss of bridged funds, matching the "permanent freezing of bridged funds" critical impact category.

### Likelihood Explanation

Any non-deployed NEP-141 token that implements a blacklist, pause, or custom transfer restriction can trigger this. USDC (Circle's token) is a prominent example with a well-known blacklist mechanism and has a NEAR representation. A user whose NEAR address is blacklisted by such a token after initiating a cross-chain transfer (but before finalization) will have their funds permanently frozen. A malicious actor could also self-blacklist to grief the protocol's accounting. The relayer-driven `fin_transfer` call is the only entry point needed.

### Recommendation

In `fin_transfer_send_tokens_callback`, check the promise result even when `is_ft_transfer_call = false`. If the `ft_transfer` promise failed, revert the lock actions and remove the finalization record (mirroring the existing refund path). Alternatively, restructure `process_fin_transfer_to_near` so that `add_fin_transfer` is only called inside the callback after confirming the token transfer succeeded.

### Proof of Concept

1. Token `T` is a non-deployed NEP-141 token with a blacklist. The bridge holds 1000 `T` in escrow for a pending inbound transfer to NEAR recipient `alice.near`.
2. `alice.near` is added to `T`'s blacklist (e.g., by the token issuer).
3. A relayer calls `fin_transfer` with a valid proof. `process_fin_transfer_to_near` runs:
   - `add_fin_transfer(transfer_id)` → transfer ID is now in `finalised_transfers`.
   - `send_tokens(T, alice.near, 1000, "")` → issues `ft_transfer(alice.near, 1000)`.
   - `ft_transfer` panics because `alice.near` is blacklisted → promise result is `Failed`.
4. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
5. `is_refund_required(false)` returns `false` → callback takes the success path.
6. `FinTransferEvent` is emitted. Fees are sent. No revert occurs.
7. The 1000 `T` tokens remain in the bridge contract. The transfer ID is in `finalised_transfers` and cannot be re-submitted. Funds are permanently frozen. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1692-1747)
```rust
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
        let token = self.get_token_id(&transfer_message.token);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L1783-1804)
```rust
impl Contract {
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

**File:** near/omni-bridge/src/lib.rs (L1875-1878)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
```

**File:** near/omni-bridge/src/lib.rs (L1967-1977)
```rust
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(SEND_TOKENS_CALLBACK_GAS)
                .fin_transfer_send_tokens_callback(
                    transfer_message,
                    &fee_recipient,
                    !msg.is_empty(),
                    predecessor_account_id,
                    lock_actions,
                ),
        )
```

**File:** near/omni-bridge/src/lib.rs (L2056-2118)
```rust
    fn send_tokens(
        &self,
        token: AccountId,
        recipient: AccountId,
        amount: U128,
        msg: &str,
    ) -> Promise {
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);

        let is_deployed_token = self.is_deployed_token(&token);

        if token == self.wnear_account_id && msg.is_empty() {
            // Unwrap wNEAR and transfer NEAR tokens
            ext_wnear_token::ext(self.wnear_account_id.clone())
                .with_static_gas(WNEAR_WITHDRAW_GAS)
                .with_attached_deposit(ONE_YOCTO)
                .near_withdraw(amount)
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(NEAR_WITHDRAW_CALLBACK_GAS)
                        .near_withdraw_callback(recipient, NearToken::from_yoctonear(amount.0)),
                )
        } else if is_deployed_token {
            let deposit = if msg.is_empty() {
                NO_DEPOSIT
            } else {
                ONE_YOCTO
            };

            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(ft_transfer_call_gas)
                .ft_transfer_call(recipient, amount, None, msg.to_string())
        }
    }
```
