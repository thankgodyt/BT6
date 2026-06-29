### Title
Permanent Loss of Bridged Tokens When `ft_transfer_call` Fails With a Panic in `fin_transfer` Flow — (`near/omni-bridge/src/lib.rs`)

### Summary

When a user bridges tokens to NEAR with a non-empty `msg` field (e.g., DEX swap instructions), the bridge calls `ft_transfer_call` on the recipient contract. If the recipient's `ft_on_transfer` panics (e.g., slippage exceeded, outdated swap parameters), the promise result is `PromiseResult::Failed`. The `is_refund_required` helper treats this `Err` case as a non-refund scenario (`false`), so `fin_transfer_send_tokens_callback` emits a success event and leaves the transfer permanently finalized — while the tokens are either stuck in the bridge contract (non-deployed tokens) or never minted (deployed tokens). There is no recovery path.

### Finding Description

The `fin_transfer` flow on NEAR finalizes an inbound cross-chain transfer. When the recipient is a NEAR account and the transfer carries a `msg` payload, `process_fin_transfer_to_near` calls `send_tokens`, which dispatches `ft_transfer_call` (non-deployed tokens) or `mint(..., Some(msg))` (deployed tokens). Both paths invoke `ft_on_transfer` on the recipient contract.

The callback `fin_transfer_send_tokens_callback` delegates to `is_refund_required` to decide whether to burn/revert or finalize:

```rust
// near/omni-bridge/src/lib.rs  lines 1784-1804
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    amount.0 == 0   // ← refund when receiver used 0 tokens (failure)
                } else {
                    false           // ← unexpected: don't refund
                }
            }
            Err(_) => false,        // ← BUG: panic treated as success
        }
    } else {
        false
    }
}
```

The `Err(_)` arm — reached whenever the cross-contract call panics — returns `false`, causing the callback to take the "success" branch:

```rust
// near/omni-bridge/src/lib.rs  lines 1700-1746
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(...);
    self.revert_lock_actions(&lock_actions);
    self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);
    // emit FailedFinTransferEvent
} else {
    // emit FinTransferEvent  ← taken on Err, tokens are stuck
}
```

Because `remove_fin_transfer` is never called, the transfer ID remains in `finalised_transfers`, making re-submission of the same proof impossible. The tokens are permanently inaccessible.

The same `is_refund_required` function is shared by `resolve_fast_transfer` and `resolve_utxo_fin_transfer`, so the same defect affects those paths too.

### Impact Explanation

**For non-deployed (locked) tokens**: `ft_transfer_call` reverts on panic; tokens remain in the bridge contract with no withdrawal function available to the user. The transfer is finalized and cannot be retried.

**For deployed (mintable) tokens**: `mint(..., Some(msg))` reverts on panic; no tokens are ever minted. The source-chain tokens were already burned. The user suffers a total, unrecoverable loss.

This satisfies the "permanent freezing / loss of bridged funds" critical impact criterion.

### Likelihood Explanation

Any user who bridges tokens to NEAR with a non-empty `msg` (e.g., to trigger a DEX swap on arrival) is exposed. Cross-chain relay latency routinely causes swap parameters (minimum output, deadline) to expire. A single market move during relay is sufficient to cause `ft_on_transfer` to panic on the DEX contract, triggering the bug. This is the same external-factor scenario rated Medium in the original report; it is realistic and user-reachable without any privileged access.

### Recommendation

In `is_refund_required`, treat `Err` (promise panic) as a refund-required condition, mirroring the `amount.0 == 0` case:

```rust
Err(_) => true,  // ft_transfer_call panicked → tokens not delivered → refund
```

This ensures `fin_transfer_send_tokens_callback` burns/reverts and removes the finalization record, allowing the proof to be re-submitted or an alternative recovery path to be taken.

### Proof of Concept

1. User calls `initTransfer` on EVM with `message = "<dex-swap-params>"` and a tight slippage bound.
2. Relayer submits proof to NEAR `fin_transfer`.
3. `fin_transfer_callback` → `process_fin_transfer_to_near` → `send_tokens` dispatches `ft_transfer_call(dex_contract, amount, None, "<dex-swap-params>")`.
4. By the time the cross-chain relay completes, the market has moved; the DEX's `ft_on_transfer` panics with "slippage exceeded".
5. `ft_transfer_call` reverts; tokens remain in the bridge contract.
6. `fin_transfer_send_tokens_callback` is invoked; `is_refund_required` hits `Err(_) => false`.
7. Bridge emits `FinTransferEvent` (success). Transfer ID is in `finalised_transfers`.
8. User's tokens are permanently stuck; no re-submission is possible.

Key file references: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1700-1718)
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

**File:** near/omni-bridge/src/lib.rs (L1957-1978)
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
    }
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
