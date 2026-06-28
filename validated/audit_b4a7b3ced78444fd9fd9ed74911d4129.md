### Title
Permanent Loss of Bridged Funds When `ft_transfer`/`mint` to Recipient Fails Due to Token-Level Restriction — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

When finalizing an inbound transfer to a NEAR recipient, the bridge marks the transfer as finalized and decrements the locked-token counter **before** the token delivery succeeds. If the underlying `ft_transfer` or `mint` call fails (e.g., because the recipient is blacklisted in a NEP-141 token such as USDC), the callback `fin_transfer_send_tokens_callback` treats the failure as a non-refund case, logs a success event, and leaves the transfer permanently finalized. The user's tokens are irretrievably lost and the bridge's locked-token accounting is corrupted.

---

### Finding Description

**Entry path:** A relayer calls `fin_transfer` for a valid cross-chain transfer whose NEAR recipient is blacklisted in the bridged NEP-141 token.

**Step 1 — Transfer finalized before delivery.**
`process_fin_transfer_to_near` calls `add_fin_transfer` (consuming the nonce) and `unlock_tokens_if_needed` (decrementing `locked_tokens`) before any token delivery occurs. [1](#0-0) 

**Step 2 — Token delivery pushed to recipient.**
`send_tokens` issues an `ft_transfer` (for non-deployed tokens, no `msg`) or `mint` (for deployed tokens) to the recipient. Both are chained with `.then(fin_transfer_send_tokens_callback(..., is_ft_transfer_call = false, ...))`. [2](#0-1) [3](#0-2) 

**Step 3 — Failed delivery is silently ignored.**
`is_refund_required` is called with `is_ft_transfer_call = false` (because `msg` is empty). It unconditionally returns `false`, regardless of whether the preceding `ft_transfer`/`mint` promise succeeded or failed. [4](#0-3) 

**Step 4 — Callback takes the success branch.**
Because `is_refund_required` returned `false`, the callback skips `revert_lock_actions` and `remove_fin_transfer`, sends the fee to the relayer (detached), and emits `FinTransferEvent` — as if the transfer succeeded. [5](#0-4) 

**Root cause:** `is_refund_required` treats a failed promise as "no refund needed" in both branches — for `ft_transfer_call` it returns `false` on `Err(_)`, and for plain `ft_transfer` it always returns `false`. [4](#0-3) 

---

### Impact Explanation

Two simultaneous harms occur:

1. **Permanent loss of bridged funds.** The transfer nonce is consumed (`finalised_transfers` entry persists), so the transfer cannot be retried. The user's tokens are never delivered and cannot be recovered.

2. **Locked-token accounting corruption.** `unlock_tokens_if_needed` decremented `locked_tokens` for the origin chain before delivery. Because `revert_lock_actions` is never called on failure, the bridge permanently under-counts locked tokens. This mis-accounting can allow future transfers to over-mint or over-release tokens beyond what is actually escrowed on the source chain. [6](#0-5) [7](#0-6) 

---

### Likelihood Explanation

USDC is a first-class bridged asset on NEAR. The USDC NEP-141 contract implements a blacklist; `ft_transfer` to a blacklisted account panics, causing the cross-contract promise to fail. Any user whose NEAR address is added to the USDC blacklist after initiating a cross-chain transfer (or who is already blacklisted) triggers this path. The relayer has no way to detect this before submission, and no off-chain fallback exists. The same applies to any other NEP-141 token that enforces transfer restrictions.

---

### Recommendation

In `fin_transfer_send_tokens_callback`, inspect the promise result for **all** transfer types (not only `ft_transfer_call`). If the token delivery promise failed, treat it as a refund case: call `revert_lock_actions`, call `remove_fin_transfer`, and emit `FailedFinTransferEvent`. Concretely:

```rust
// Replace the current is_refund_required check with:
let delivery_failed = match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
    Err(_) => true,   // promise panicked / failed
    Ok(value) if is_ft_transfer_call => {
        serde_json::from_slice::<U128>(&value).map_or(false, |u| u.0 == 0)
    }
    Ok(_) => false,
};
if delivery_failed { /* revert */ } else { /* send fee */ }
```

This ensures a failed `ft_transfer` or `mint` is always treated as a refund, restoring locked-token accounting and preventing permanent fund loss.

---

### Proof of Concept

1. User bridges USDC from Ethereum to NEAR; recipient is `alice.near`.
2. After the source-chain event is emitted, `alice.near` is added to the USDC blacklist on NEAR.
3. Relayer calls `fin_transfer` with a valid proof and storage deposit for `alice.near`.
4. `process_fin_transfer_to_near` runs: nonce consumed, `locked_tokens[Eth][usdc]` decremented.
5. `ft_transfer(alice.near, amount)` panics inside the USDC contract → promise result = `Failed`.
6. `fin_transfer_send_tokens_callback` runs: `is_refund_required(false)` → `false`.
7. Callback enters `else` branch: fee minted to relayer (detached), `FinTransferEvent` emitted.
8. `alice.near` receives zero tokens. Transfer cannot be retried (nonce consumed). `locked_tokens` is permanently under-counted. [8](#0-7) [9](#0-8)

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

**File:** near/omni-bridge/src/lib.rs (L1867-1978)
```rust
    #[allow(clippy::too_many_lines, clippy::ptr_arg)]
    fn process_fin_transfer_to_near(
        &mut self,
        recipient: AccountId,
        predecessor_account_id: &AccountId,
        transfer_message: TransferMessage,
        storage_deposit_actions: &Vec<StorageDepositAction>,
    ) -> Promise {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];

        // If fast transfer happened, change recipient and fee recipient to the relayer that executed fast transfer
        let (recipient, msg, fee_recipient) = match fast_transfer_status {
            Some(status) => {
                require!(
                    !status.finalised,
                    BridgeError::FastTransferAlreadyFinalised.as_ref()
                );
                self.remove_fast_transfer(&fast_transfer.id());
                (status.relayer.clone(), String::new(), status.relayer)
            }
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
        };

        let mut storage_deposit_action_index: usize = 0;
        require!(
            Self::check_storage_balance_result(
                (storage_deposit_action_index + 1)
                    .try_into()
                    .near_expect(BridgeError::Cast)
            ) && storage_deposit_actions[storage_deposit_action_index].account_id == recipient
                && storage_deposit_actions[storage_deposit_action_index].token_id == token,
            BridgeError::StorageRecipientOmitted.as_ref()
        );
        storage_deposit_action_index += 1;

        // One yoctoNear is required to send tokens to the recipient
        required_balance = required_balance.saturating_add(ONE_YOCTO);

        if transfer_message.fee.fee.0 > 0 {
            require!(
                Self::check_storage_balance_result(
                    (storage_deposit_action_index + 1)
                        .try_into()
                        .near_expect(BridgeError::Cast)
                ) && storage_deposit_actions[storage_deposit_action_index].account_id
                    == fee_recipient
                    && storage_deposit_actions[storage_deposit_action_index].token_id == token,
                BridgeError::StorageFeeRecipientOmitted.as_ref()
            );
            storage_deposit_action_index += 1;

            required_balance = required_balance.saturating_add(ONE_YOCTO);
        }

        if transfer_message.fee.native_fee.0 > 0 {
            let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

            require!(
                Self::check_storage_balance_result(
                    (storage_deposit_action_index + 1)
                        .try_into()
                        .near_expect(BridgeError::Cast)
                ) && storage_deposit_actions[storage_deposit_action_index].account_id
                    == fee_recipient
                    && storage_deposit_actions[storage_deposit_action_index].token_id
                        == native_token_id,
                BridgeError::StorageNativeFeeRecipientOmitted.as_ref()
            );
        }

        self.update_storage_balance(
            predecessor_account_id.clone(),
            required_balance,
            env::attached_deposit(),
        );

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

**File:** near/omni-bridge/src/lib.rs (L2102-2107)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
```
