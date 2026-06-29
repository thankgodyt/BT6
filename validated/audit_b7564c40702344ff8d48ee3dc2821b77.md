### Title
`fin_transfer_send_tokens_callback` Silently Ignores `ft_transfer` Failure, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`fin_transfer_send_tokens_callback` in the NEAR bridge contract does not check the promise result when `send_tokens` dispatches a plain `ft_transfer` (i.e., when `msg` is empty). The helper `is_refund_required` hard-codes `false` for every non-`ft_transfer_call` path. If the underlying `ft_transfer` panics — for example because the recipient is blacklisted by a USDC-style token — the callback silently treats the failed delivery as a success: it emits `FinTransferEvent`, pays the relayer fee, and leaves the transfer permanently recorded in `finalised_transfers`. The user's funds are irretrievably frozen: the origin-chain proof can never be re-submitted (replay protection), and the locked-token accounting on NEAR is already decremented.

### Finding Description

**`is_refund_required` is blind to plain `ft_transfer` failures** [1](#0-0) 

The function only inspects the promise result when `is_ft_transfer_call == true`. For every other case it unconditionally returns `false` — including the case where `send_tokens` dispatched a plain `ft_transfer` that panicked.

**`send_tokens` uses plain `ft_transfer` for non-deployed tokens with an empty `msg`** [2](#0-1) 

The callback is then scheduled with `is_ft_transfer_call = !msg.is_empty()`, which evaluates to `false`. [3](#0-2) 

**`process_fin_transfer_to_near` marks the transfer finalized *before* the token send** [4](#0-3) 

`add_fin_transfer` inserts the transfer ID into `finalised_transfers` and decrements `locked_tokens` via `unlock_tokens_if_needed` (line 1881–1885). Both state mutations persist even when the subsequent `ft_transfer` fails, because they occurred in an earlier NEAR receipt that has already committed.

**The callback takes the "success" branch on failure** [5](#0-4) 

Because `is_refund_required` returns `false`, the `else` branch executes: the relayer fee is paid and `FinTransferEvent` is emitted — even though the recipient received nothing. The correct recovery path (`burn_tokens_if_needed`, `revert_lock_actions`, `remove_fin_transfer`, `FailedFinTransferEvent`) is never taken.

The same structural defect exists in `resolve_fast_transfer` and `resolve_utxo_fin_transfer`, which share the same `is_refund_required` helper. [6](#0-5) [7](#0-6) 

### Impact Explanation

For any non-deployed (native NEAR) token whose contract can reject an `ft_transfer` — a USDC-style blacklist, a paused token, or any custom rejection logic — the following permanent state results:

1. The origin-chain proof is consumed; `finalised_transfers` blocks any re-submission.
2. `locked_tokens` is decremented, so the bridge's internal accounting no longer reflects the actual on-chain balance.
3. The recipient never receives tokens; they remain stranded in the bridge contract.
4. The relayer collects its fee for a delivery that never occurred.

The user's bridged funds are permanently frozen with no recovery path.

### Likelihood Explanation

USDC and USDC.e are among the most commonly bridged assets. USDC's blacklist is actively maintained by Circle. A user whose NEAR address is blacklisted after initiating a bridge transfer — or who mistakenly specifies a blacklisted address — triggers this path with no warning and no recourse. The code path is reached on every standard (no-`msg`) inbound `fin_transfer` for a non-deployed token, making it a realistic production scenario.

### Recommendation

In `fin_transfer_send_tokens_callback` (and the analogous `resolve_fast_transfer` / `resolve_utxo_fin_transfer`), check the promise result unconditionally, not only when `is_ft_transfer_call` is true. Extend `is_refund_required` (or add a separate check) to inspect `env::promise_result_checked(0, …)` for the plain `ft_transfer` case and treat a failed promise as requiring a refund: revert lock actions, remove the finalized-transfer record, and emit `FailedFinTransferEvent` instead of `FinTransferEvent`.

### Proof of Concept

1. Deploy a NEAR token contract that rejects `ft_transfer` to a specific address (simulating a USDC blacklist).
2. Register that token with the bridge as a non-deployed (locked) token.
3. Lock tokens in the EVM bridge and submit a valid `fin_transfer` proof to the NEAR bridge targeting the blacklisted NEAR address with an empty `msg`.
4. Observe that `fin_transfer_callback` → `process_fin_transfer_to_near` → `add_fin_transfer` commits the transfer to `finalised_transfers` and decrements `locked_tokens`.
5. The `ft_transfer` to the blacklisted address panics; `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
6. `is_refund_required(false)` returns `false`; the callback emits `FinTransferEvent` and pays the fee.
7. Confirm: the recipient balance is zero, `finalised_transfers` contains the transfer ID (preventing retry), `locked_tokens` is decremented, and the tokens remain in the bridge contract — permanently frozen.

### Citations

**File:** near/omni-bridge/src/lib.rs (L896-911)
```rust
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
```

**File:** near/omni-bridge/src/lib.rs (L1014-1043)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn resolve_utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> U128 {
        let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            amount
        } else {
            env::log_str(
                &OmniBridgeEvent::UtxoTransferEvent {
                    token_id,
                    amount,
                    utxo_transfer_message: utxo_fin_transfer_msg,
                    new_transfer_id: None,
                }
                .to_log_string(),
            );

            U128(0)
        }
```

**File:** near/omni-bridge/src/lib.rs (L1702-1745)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L1784-1803)
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
```

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
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

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```
