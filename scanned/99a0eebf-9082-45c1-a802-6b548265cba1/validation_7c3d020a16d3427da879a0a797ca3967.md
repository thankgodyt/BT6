### Title
`is_refund_required` Returns `false` on Promise Failure, Permanently Locking Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary

In `fin_transfer_send_tokens_callback`, the helper `is_refund_required` silently returns `false` when the underlying `ft_transfer_call` (or `ft_transfer`) promise result is `Err`. This causes the bridge to skip all cleanup — it does not revert the `locked_tokens` accounting, does not remove the finalization record, and incorrectly emits a success event. The user's bridged funds are permanently frozen inside the bridge contract with no recovery path.

### Finding Description

The `fin_transfer` flow for NEAR-recipient transfers is:

1. `fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_near`
2. Inside `process_fin_transfer_to_near`:
   - `add_fin_transfer` records the transfer as finalized (replay-prevention)
   - `unlock_tokens_if_needed` decrements `locked_tokens[origin_chain][token]`
   - `send_tokens` dispatches `ft_transfer_call` (or `ft_transfer`) to the token contract
3. `fin_transfer_send_tokens_callback` is called as the callback [1](#0-0) 

Inside the callback, `is_refund_required` decides whether to clean up: [2](#0-1) 

The critical branch is:

```rust
// Unexpected case: don't refund
Err(_) => false,
```

When the `ft_transfer_call` promise itself fails (i.e., the token contract panics — e.g., it is paused, has a minimum-transfer guard, or runs out of gas), NEAR returns a `Failed` promise result. `env::promise_result_checked` returns `Err(_)`, and `is_refund_required` returns `false`.

With `is_refund_required == false`, the callback takes the **success path**: [3](#0-2) 

- `revert_lock_actions` is **not** called → `locked_tokens` counter stays decremented even though the tokens never left the bridge.
- `remove_fin_transfer` is **not** called → the finalization record remains, blocking any future re-submission.
- A `FinTransferEvent` (success) is emitted even though the transfer failed.

The `send_tokens` function dispatches either `ft_transfer_call` (non-empty `msg`) or `ft_transfer` (empty `msg`) to the token contract: [4](#0-3) 

The `is_ft_transfer_call` flag passed to the callback is `!msg.is_empty()`: [5](#0-4) 

For the `ft_transfer` (empty-msg) path, `is_ft_transfer_call = false`, so `is_refund_required` always returns `false` regardless of the promise outcome — the same broken path applies if `ft_transfer` itself fails.

### Impact Explanation

When `ft_transfer_call` or `ft_transfer` fails with a promise error:

1. **Funds permanently frozen**: The tokens are still held in the bridge's account (the failed call is atomically reverted by NEAR), but the finalization record blocks any re-submission. There is no admin escape hatch or retry mechanism.
2. **Balance mis-accounting**: `locked_tokens[origin_chain][token]` is permanently decremented below its true value. Over time this allows the bridge to over-unlock tokens on future transfers, breaking the escrow invariant.
3. **False success event**: `FinTransferEvent` is emitted, misleading off-chain relayers and indexers into believing the transfer succeeded.

This matches the **Critical** impact class: permanent freezing of bridged funds and escrow mis-accounting.

### Likelihood Explanation

The `Err` branch is reachable without any privileged access whenever the destination token contract rejects the call before completing the transfer. Concrete realistic triggers:

- The token contract has a **pause** mechanism (common in production ERC-20/NEP-141 tokens) and is paused at the moment of finalization.
- The token contract enforces a **minimum transfer amount** that the bridged amount does not meet.
- The token contract is **upgraded** between proof submission and callback execution, changing its interface.
- **Gas exhaustion** inside the token contract's `ft_transfer_call` logic (the bridge allocates gas dynamically but cannot control the token contract's internal consumption).

None of these require attacker privilege; any user whose transfer happens to coincide with such a condition loses their funds permanently.

### Recommendation

Handle the `Err` branch in `is_refund_required` as a cleanup-required case, not a silent success:

```rust
// Unexpected case: treat as refund-required so cleanup runs
Err(_) => true,
```

Alternatively, add a dedicated `Err` arm in `fin_transfer_send_tokens_callback` that calls `revert_lock_actions`, `remove_fin_transfer`, and emits `FailedFinTransferEvent`, mirroring the existing refund path. This ensures that regardless of *why* the token transfer failed, the bridge's state is always left consistent and the user's funds are not permanently frozen.

### Proof of Concept

1. Deploy a NEP-141 token contract that supports a `pause` function. Register it as a non-deployed (locked) token in the bridge.
2. Initiate a cross-chain transfer from Ethereum to a NEAR recipient with a non-empty `msg` field.
3. Before the relayer calls `fin_transfer`, pause the token contract.
4. The relayer calls `fin_transfer` with a valid proof. `process_fin_transfer_to_near` runs: `add_fin_transfer` records the transfer, `unlock_tokens_if_needed` decrements `locked_tokens`, and `send_tokens` dispatches `ft_transfer_call` to the paused token contract.
5. The token contract panics (paused). The promise result is `Failed`.
6. `fin_transfer_send_tokens_callback` is invoked. `is_refund_required` hits `Err(_) => false` at line 1798 and returns `false`.
7. The callback takes the success path: `revert_lock_actions` is skipped, `remove_fin_transfer` is skipped, `FinTransferEvent` is emitted.
8. Observe: the user's tokens are not received; `get_transfer_message` for the transfer ID panics with `TransferNotExist` (fin record was never removed — it was stored in `finalized_transfers`, not `pending_transfers`); `locked_tokens` is permanently lower than the actual bridge balance; no recovery is possible. [2](#0-1) [6](#0-5) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1700-1746)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1875-1885)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

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

**File:** near/omni-bridge/src/lib.rs (L2056-2117)
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
```
