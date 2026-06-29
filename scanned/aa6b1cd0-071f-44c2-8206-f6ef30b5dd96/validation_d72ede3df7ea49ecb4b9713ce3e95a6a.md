### Title
Unchecked `ft_transfer` Failure in `fin_transfer_send_tokens_callback` Causes Permanent Loss of Bridged Funds - (File: near/omni-bridge/src/lib.rs)

### Summary

When finalizing a bridge transfer to a NEAR recipient for a non-deployed (externally-locked) token with no message, the `fin_transfer_send_tokens_callback` never checks whether the underlying `ft_transfer` promise succeeded or failed. If `ft_transfer` panics (e.g., gas exhaustion, token-specific rejection), the callback silently proceeds as if the transfer succeeded: the finalization record is kept, locked tokens remain unlocked, and the user's funds are permanently lost with no recovery path.

### Finding Description

In `send_tokens`, when the token is non-deployed and `msg` is empty, a plain `ft_transfer` is dispatched: [1](#0-0) 

The callback chained after this is `fin_transfer_send_tokens_callback`, called with `is_ft_transfer_call = !msg.is_empty()`: [2](#0-1) 

Inside `fin_transfer_send_tokens_callback`, the refund/revert path is gated entirely on `is_refund_required(is_ft_transfer_call)`: [3](#0-2) 

And `is_refund_required` with `is_ft_transfer_call = false` unconditionally returns `false` — it never inspects the promise result: [4](#0-3) 

So when `msg.is_empty()` (the common case for a simple withdrawal), the callback **never checks** whether `ft_transfer` succeeded. If `ft_transfer` panics (its state changes are rolled back by the NEAR runtime, but the callback still executes), the callback falls into the `else` branch: [5](#0-4) 

This means:
- The `lock_actions` (which recorded the `unlock_tokens_if_needed` done in `process_fin_transfer_to_near`) are **not reverted** — locked token accounting is permanently decremented.
- The finalization record is **not removed** — the nonce is consumed, so the transfer cannot be re-processed.
- The fee is sent to the fee recipient as if the transfer succeeded.
- The user receives nothing.

The locked tokens were decremented here before `send_tokens` was called: [6](#0-5) 

### Impact Explanation

For any non-deployed (externally-locked) token bridged from EVM/Solana/etc. to NEAR with no message, if the `ft_transfer` call fails:

1. The origin-chain locked token counter is permanently decremented (tokens are "released" from escrow accounting without being delivered).
2. The destination nonce is consumed — the proof cannot be replayed.
3. The user's bridged funds are permanently lost with no recovery mechanism.

This is a critical loss of bridged funds: the escrow mis-accounting means the bridge will allow future withdrawals on the origin chain for tokens that were never actually delivered on NEAR.

### Likelihood Explanation

`ft_transfer` on NEAR panics (rather than returning `false`) when it fails, which means the NEAR runtime rolls back the token transfer state but still executes the callback. Failure conditions include:

- **Gas exhaustion**: `FT_TRANSFER_GAS` is a static allocation; if the token contract consumes more gas than allocated, the call fails.
- **Token-specific rejection**: Some NEP-141 tokens implement custom `ft_transfer` logic that can panic for reasons beyond storage registration (e.g., blacklists, paused state, transfer limits).
- **Recipient not registered**: Although storage deposit actions are checked before the transfer, a race condition or incorrect storage deposit amount could leave the recipient unregistered.

The `ft_transfer_call` path (when `msg` is non-empty) correctly checks the promise result via `is_refund_required`. The plain `ft_transfer` path (when `msg` is empty) has no such check — this asymmetry is the root cause.

### Recommendation

In `fin_transfer_send_tokens_callback`, also check the promise result when `is_ft_transfer_call = false`. The simplest fix is to check `env::promise_result_checked(0, ...)` regardless of whether it was a `ft_transfer` or `ft_transfer_call`, and revert lock actions + remove the fin transfer record if the promise failed:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    // Check promise result for both ft_transfer and ft_transfer_call
    match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
        Err(_) => true, // ft_transfer panicked — always refund
        Ok(value) if is_ft_transfer_call => {
            // ft_transfer_call: refund if ft_on_transfer returned 0 (unused)
            near_sdk::serde_json::from_slice::<U128>(&value)
                .map_or(false, |amount| amount.0 == 0)
        }
        Ok(_) => false, // ft_transfer succeeded
    }
}
```

### Proof of Concept

1. Alice locks 1000 USDC on Ethereum and initiates a bridge transfer to NEAR (no message).
2. A relayer calls `fin_transfer` with the proof. `process_fin_transfer_to_near` decrements `locked_tokens[Eth][usdc]` by 1000 and calls `send_tokens`.
3. `send_tokens` dispatches `ft_transfer(alice.near, 1000)` with `FT_TRANSFER_GAS`.
4. The USDC token contract on NEAR panics (e.g., gas exhaustion or blacklist). The NEAR runtime rolls back the token transfer but schedules `fin_transfer_send_tokens_callback`.
5. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
6. `is_refund_required(false)` returns `false` without inspecting the promise result.
7. The callback logs `FinTransferEvent` and sends the fee to the relayer.
8. Alice's 1000 USDC are permanently lost: the NEAR token was never transferred, the Ethereum escrow counter was decremented, and the nonce is consumed preventing replay. [7](#0-6) [4](#0-3) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1690-1747)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
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

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
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

**File:** near/omni-bridge/src/lib.rs (L2102-2117)
```rust
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
```
