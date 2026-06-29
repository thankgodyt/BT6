### Title
Unconditional State Update Before Confirming Token Transfer Success in Fast Transfer Reimbursement - (File: `near/omni-bridge/src/lib.rs`)

### Summary
In `process_fin_transfer_to_other_chain`, when a fast transfer relayer is owed reimbursement, the bridge fires `send_tokens(...).detach()` — discarding the promise result — and then unconditionally calls `mark_fast_transfer_as_finalised`. If the token transfer to the relayer fails, the fast transfer is permanently marked as finalised and the relayer's pre-funded tokens are irrecoverably lost, with no rollback of the already-updated `locked_tokens` accounting.

### Finding Description

In `process_fin_transfer_to_other_chain`, when a fast transfer has been previously performed for a cross-chain transfer (non-NEAR destination), the bridge is supposed to reimburse the relayer who pre-funded the recipient. The code does:

```rust
if let Some(relayer) = recipient {
    self.send_tokens(token, relayer, U128(...), "").detach();
    self.mark_fast_transfer_as_finalised(&fast_transfer.id());
}
``` [1](#0-0) 

The `.detach()` call fires the token transfer promise but registers **no callback** — the result (success or failure) is completely ignored. Immediately after, `mark_fast_transfer_as_finalised` permanently records the fast transfer as done. Prior to this block, `unlock_tokens_if_needed` and `lock_tokens_if_needed` have already mutated `locked_tokens`: [2](#0-1) 

If `send_tokens` fails (e.g., `ft_transfer` panics because the relayer account has no storage registered for the token, or the token contract itself reverts), all three state mutations — `unlock_tokens`, `lock_tokens`, and `mark_fast_transfer_as_finalised` — remain committed with no revert path.

The same pattern exists in `utxo_fin_transfer_fast`, where `remove_fast_transfer` or `mark_fast_transfer_as_finalised` is called before `send_tokens(...).detach()`: [3](#0-2) 

By contrast, the NEAR-destination path correctly uses a callback (`resolve_fast_transfer`) to handle failure: [4](#0-3) 

The `send_fee_internal` function also fires native-fee transfers with `.detach()` after the transfer message has already been removed from state: [5](#0-4) 

### Impact Explanation

When `send_tokens` to the relayer fails silently:

1. For **non-deployed (native) tokens**: the tokens remain locked in the bridge contract under no claimable state — the fast transfer is finalised so no one can re-trigger reimbursement, and the `locked_tokens` counter is already decremented for the origin chain. The relayer's pre-funded amount is permanently frozen in the bridge.
2. For **deployed (bridged) tokens**: `mint` is never called, so the relayer simply never receives their reimbursement. Their pre-funded tokens on the destination chain are permanently lost.

This constitutes permanent loss/freezing of bridged funds for the relayer, matching the "Critical — loss or permanent freezing of bridged funds" impact category.

### Likelihood Explanation

The `ft_transfer` call inside `send_tokens` for non-deployed tokens requires the recipient (relayer) to have a storage deposit registered with the token contract. If the relayer account lacks this storage registration, the transfer fails. A relayer who performs a fast transfer for a token they have not previously registered storage for will trigger this silently. Additionally, any transient failure in the token contract (panic, out-of-gas in the token's `ft_transfer` handler) produces the same outcome. The entry path is reachable by any trusted relayer performing a fast transfer on a cross-chain (non-NEAR destination) route.

### Recommendation

Replace `.detach()` with a proper callback that checks the transfer result before committing `mark_fast_transfer_as_finalised`. If the token transfer fails, the callback should revert the `locked_tokens` changes using `revert_lock_actions` (which already exists for this purpose) and remove the finalised-transfer record, allowing the relayer to retry. This mirrors the pattern already used in the NEAR-destination fast transfer path via `resolve_fast_transfer`. [6](#0-5) 

### Proof of Concept

1. Trusted relayer R performs a fast transfer for a cross-chain transfer T (origin: Eth → destination: Sol), pre-funding the recipient on Solana. The bridge records `fast_transfers[T.id] = { relayer: R, finalised: false }`.
2. The canonical `fin_transfer` is called (by any trusted relayer) with a valid proof of T.
3. `process_fin_transfer_to_other_chain` runs: `unlock_tokens_if_needed` decrements `locked_tokens[Eth][token]`, `lock_tokens_if_needed` increments `locked_tokens[Sol][token]` for the fee portion.
4. `send_tokens(token, R, amount_without_fee, "").detach()` fires an `ft_transfer` to R. R's account has no storage deposit for `token` on NEAR, so the `ft_transfer` panics inside the token contract. The promise fails silently — no callback observes this.
5. `mark_fast_transfer_as_finalised` is called unconditionally, setting `fast_transfers[T.id].finalised = true`.
6. R never receives their reimbursement. The tokens remain in the bridge with no claimable path. The `locked_tokens` accounting is permanently skewed. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1997-2006)
```rust
        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );
```

**File:** near/omni-bridge/src/lib.rs (L2027-2041)
```rust
        // If fast transfer happened, send tokens to the relayer that executed fast transfer
        if let Some(relayer) = recipient {
            self.send_tokens(
                token,
                relayer,
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
                "",
            )
            .detach();
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
        } else {
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

**File:** near/omni-bridge/src/lib.rs (L2529-2548)
```rust
        let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
            self.remove_fast_transfer(&fast_transfer.id());
            fast_transfer.amount
        } else {
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
            // With transfers to other chain the fee will be claimed after finalization on the destination chain
            U128(
                fast_transfer
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            )
        };

        self.send_tokens(
            fast_transfer.token_id.clone(),
            fast_transfer_status.relayer,
            amount,
            "",
        )
        .detach();
```

**File:** near/omni-bridge/src/lib.rs (L2664-2673)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L2877-2892)
```rust

```

**File:** near/omni-bridge/src/token_lock.rs (L122-142)
```rust
    pub fn revert_lock_actions(&mut self, lock_actions: &[LockAction]) {
        for lock_action in lock_actions {
            match lock_action {
                LockAction::Locked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.unlock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unlocked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.lock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unchanged => {}
            }
        }
    }
```
