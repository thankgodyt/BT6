### Title
Unchecked `ft_transfer` Result in Callbacks Causes Permanent Loss of Bridged Funds — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`is_refund_required` only inspects the promise result when `is_ft_transfer_call == true`. When `is_ft_transfer_call == false` (i.e., a plain `ft_transfer` was dispatched), it unconditionally returns `false` — "no refund needed" — regardless of whether the `ft_transfer` promise succeeded or failed. Three callbacks rely on this function: `fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, and `resolve_utxo_fin_transfer`. In every case, a failed `ft_transfer` is silently treated as a success, permanently finalizing the transfer while the recipient receives nothing.

---

### Finding Description

`is_refund_required` is the single gate that decides whether a failed token-send should be rolled back: [1](#0-0) 

When `is_ft_transfer_call` is `false`, the function returns `false` without reading `env::promise_result_checked`. The `is_ft_transfer_call` flag is set to `!msg.is_empty()` at the call site: [2](#0-1) 

So whenever a transfer carries an empty `msg` and the token is a non-deployed (locked) NEP-141 asset, `send_tokens` dispatches a plain `ft_transfer`: [3](#0-2) 

If that `ft_transfer` promise fails, `fin_transfer_send_tokens_callback` enters the `else` branch unconditionally: [4](#0-3) 

In the `else` branch the callback:
1. Pays the fee to the relayer (`mint` or `ft_transfer` of the fee amount).
2. Emits `FinTransferEvent`, permanently marking the transfer as finalized.
3. Does **not** call `revert_lock_actions`, so the `locked_tokens` counter that was decremented in `process_fin_transfer_to_near` is never restored.

The transfer ID was already inserted into `finalised_transfers` at the top of `process_fin_transfer_to_near`: [5](#0-4) 

The same blind spot exists in `resolve_utxo_fin_transfer`: [6](#0-5) 

And in `resolve_fast_transfer`, where `burn_tokens_if_needed` is called unconditionally before the (also blind) refund check, meaning a failed `mint` for a deployed token burns the relayer's collateral while leaving the fast-transfer record in place: [7](#0-6) 

---

### Impact Explanation

For the `fin_transfer_send_tokens_callback` path (inbound EVM/Wormhole/MPC transfer to NEAR with empty `msg`, non-deployed token):

- The transfer is permanently recorded as finalized — replay is impossible.
- `locked_tokens` for the origin chain is decremented but the tokens are never released to the recipient.
- The relayer collects the fee for a transfer that delivered nothing.
- The user's bridged funds are permanently frozen: locked on the source chain side (the source-chain contract already burned/locked them), and undelivered on NEAR.

This is a **critical** escrow mis-accounting and permanent freezing of bridged funds.

---

### Likelihood Explanation

`ft_transfer` can fail in several realistic scenarios reachable without admin compromise:

1. **Token contract paused by its own governance** — the bridge has no control over third-party NEP-141 contracts; a pause on the token side causes every in-flight `ft_transfer` to fail.
2. **Recipient account deleted or never created** — NEAR accounts can be deleted; if the recipient account no longer exists at settlement time, `ft_transfer` panics inside the token contract.
3. **Token contract upgrade introduces a panic** — a routine upgrade to the token contract between proof submission and callback execution can cause `ft_transfer` to revert.

None of these require the attacker to compromise any privileged key. A user who bridges funds to a NEAR account that is subsequently deleted, or whose token contract is paused, loses funds permanently with no recourse.

---

### Recommendation

`is_refund_required` must also inspect the promise result for the non-`ft_transfer_call` path. A minimal fix:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                near_sdk::serde_json::from_slice::<U128>(&value)
                    .map_or(false, |amount| amount.0 == 0)
            }
            Err(_) => false,
        }
    } else {
        // ft_transfer: treat any promise failure as requiring a refund/revert
        env::promise_result_checked(0, 0).is_err()
    }
}
```

Additionally, `resolve_fast_transfer` should move `burn_tokens_if_needed` into the success branch only, so a failed `mint` does not burn the relayer's collateral.

---

### Proof of Concept

1. Alice initiates a transfer of 1 000 USDC from Ethereum to her NEAR account `alice.near` with an empty `msg`. The EVM bridge contract locks 1 000 USDC.
2. A relayer submits the proof via `fin_transfer`. `process_fin_transfer_to_near` runs: the transfer is added to `finalised_transfers`, `locked_tokens[Eth][usdc]` is decremented by 1 000, and `ft_transfer(alice.near, 1000)` is dispatched to the USDC token contract.
3. Between step 2 and the callback, the USDC token contract is paused by its own governance (or `alice.near` is deleted). The `ft_transfer` promise fails.
4. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`. `is_refund_required(false)` returns `false`. The else branch fires: the relayer's fee is minted, `FinTransferEvent` is emitted.
5. Result: `finalised_transfers` contains the transfer ID (no replay possible), `locked_tokens` is permanently decremented, Alice receives 0 USDC. The 1 000 USDC remain locked on Ethereum with no mechanism to recover them. [1](#0-0) [8](#0-7) [9](#0-8)

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
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

**File:** near/omni-bridge/src/lib.rs (L2102-2107)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
```
