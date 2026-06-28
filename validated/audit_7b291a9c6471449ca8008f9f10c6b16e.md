### Title
Tokens Permanently Stuck When `send_tokens()` Fails with Promise Error in `fin_transfer_send_tokens_callback` — (File: `near/omni-bridge/src/lib.rs`)

### Summary
When the token delivery step (`send_tokens()`) inside `process_fin_transfer_to_near` fails with a NEAR promise error, `fin_transfer_send_tokens_callback` incorrectly treats the failure as a success. It emits `FinTransferEvent`, sends the fee to the relayer, and does not revert the `locked_tokens` decrement — leaving bridged tokens permanently undeliverable with no on-chain recovery path.

### Finding Description
`process_fin_transfer_to_near` orchestrates the final leg of an inbound cross-chain transfer to NEAR. It:

1. Decrements `locked_tokens` via `unlock_tokens_if_needed` (for non-deployed tokens).
2. Calls `send_tokens()`, which dispatches one of: `ft_transfer`, `ft_transfer_call`, `mint()`, or `near_withdraw → near_withdraw_callback`.
3. Chains `fin_transfer_send_tokens_callback` as the result handler. [1](#0-0) [2](#0-1) 

Inside `fin_transfer_send_tokens_callback`, the decision to revert is delegated to `is_refund_required`: [3](#0-2) 

`is_refund_required` returns `false` in two critical failure paths:

- **`ft_transfer_call` promise error** (`Err(_)` branch, line 1798): when the token contract itself panics during the transfer (e.g., token is paused, recipient account deleted between storage check and transfer, or gas exhaustion in the token contract). The comment explicitly labels this "Unexpected case: don't refund."
- **`ft_transfer` / `mint` / `near_withdraw` failure** (`is_ft_transfer_call = false` branch, line 1801–1803): when `msg` is empty, `is_ft_transfer_call` is always `false`, so any promise failure from `ft_transfer`, `mint`, or `near_withdraw_callback` also returns `false`.

When `is_refund_required` returns `false`, the callback takes the `else` branch: [4](#0-3) 

This branch:
- Sends the fee to the relayer (rewarding the relayer even though delivery failed).
- Emits `FinTransferEvent` (signaling success to off-chain observers).
- Does **not** call `revert_lock_actions`, so the `locked_tokens` decrement from step 1 is permanent.
- Does **not** call `remove_fin_transfer`, leaving the transfer in `finalised_transfers`.

Because the proof is consumed by the prover on the first call, the same proof cannot be resubmitted. The transfer is permanently finalized with no delivery and no recovery. [5](#0-4) 

### Impact Explanation
For **non-deployed (locked) tokens** (e.g., USDC, wETH bridged from Ethereum): the tokens are physically held in the bridge's balance inside the token contract. If `ft_transfer` or `ft_transfer_call` fails with a promise error, the tokens remain in the bridge's balance but `locked_tokens` has been decremented. The recipient receives nothing. There is no admin function, no retry path, and no DAO escape hatch to recover the tokens. The funds are permanently frozen in the bridge contract.

For **deployed (minted) tokens**: `mint()` failing means no tokens are created, but `FinTransferEvent` is still emitted, creating a false record of a completed transfer.

The `locked_tokens` under-count also creates a secondary accounting inconsistency: the bridge believes fewer tokens are locked than are actually present, which could allow additional outbound transfers beyond the true reserve.

### Likelihood Explanation
Medium. The trigger is a promise error from the token contract during `ft_transfer` / `ft_transfer_call`. Realistic causes include:

- **Token pause**: USDC, USDT, and many bridged ERC-20s have pause functionality. If the NEAR-side token contract is paused between the storage-check step and the `ft_transfer` step, the transfer panics.
- **Recipient account deletion**: A NEAR account can be deleted between the storage deposit check and the actual `ft_transfer`, causing the transfer to panic.
- **Gas exhaustion**: `send_tokens` computes `ft_transfer_call_gas` dynamically; if the remaining gas falls below `MIN_FT_TRANSFER_CALL_GAS`, the `require!` guard panics, which propagates as a promise error to the callback. [6](#0-5) [7](#0-6) 

None of these require privileged access; any user whose inbound transfer lands in one of these conditions is affected.

### Recommendation
In `fin_transfer_send_tokens_callback`, treat a promise error from `send_tokens()` the same as a refund: call `revert_lock_actions`, `remove_fin_transfer`, and emit `FailedFinTransferEvent`. Specifically:

- For the `ft_transfer_call` path: change the `Err(_)` arm of `is_refund_required` to return `true` (or handle it explicitly in the callback).
- For the `ft_transfer` / `mint` / `near_withdraw` path (`is_ft_transfer_call = false`): check the promise result explicitly in `fin_transfer_send_tokens_callback` and revert on error, rather than unconditionally proceeding to the success branch.

### Proof of Concept

**Scenario**: USDC (non-deployed, locked token) is paused on NEAR between the storage-check step and the `ft_transfer` step.

1. User initiates transfer of 1000 USDC from Ethereum → NEAR recipient `alice.near`.
2. Relayer calls `fin_transfer()` with valid EVM proof.
3. `fin_transfer_callback` verifies proof, calls `process_fin_transfer_to_near`.
4. `unlock_tokens_if_needed` decrements `locked_tokens[Eth][usdc.near]` by 1000.
5. `send_tokens` dispatches `ft_transfer(alice.near, 1000)` on `usdc.near`.
6. USDC contract is paused → `ft_transfer` panics → promise result is `Err(_)`.
7. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
8. `is_refund_required(false)` returns `false` unconditionally.
9. Callback enters `else` branch: sends fee to relayer, emits `FinTransferEvent`.
10. `revert_lock_actions` is never called; `locked_tokens` remains decremented by 1000.
11. `alice.near` receives 0 USDC. The proof is consumed. No retry is possible.
12. 1000 USDC remain in the bridge's balance with no on-chain recovery path. [8](#0-7) [3](#0-2) [9](#0-8)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1692-1718)
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

**File:** near/omni-bridge/src/lib.rs (L1957-1977)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
        )
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

**File:** near/omni-bridge/src/lib.rs (L2063-2067)
```rust
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);
```

**File:** near/omni-bridge/src/lib.rs (L2089-2092)
```rust
            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );
```

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```
