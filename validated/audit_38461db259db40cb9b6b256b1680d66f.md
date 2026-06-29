### Title
`ft_transfer` Failure in `fin_transfer_send_tokens_callback` Permanently Freezes Bridged Funds Without Recovery - (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

When finalizing a cross-chain transfer to a NEAR recipient, the bridge marks the transfer as finalized in `finalised_transfers` before the token push-payment is attempted. If the subsequent `ft_transfer` call fails (e.g., the recipient is blacklisted in a USDC-like token contract), the callback `fin_transfer_send_tokens_callback` does not detect the failure for non-`ft_transfer_call` paths and proceeds as if the transfer succeeded. The transfer ID remains permanently in `finalised_transfers`, the recipient never receives tokens, and there is no recovery path — bridged funds are permanently frozen.

---

### Finding Description

**Step 1 — Finalization is committed before the push-payment.**

In `process_fin_transfer_to_near`, the very first action is:

```rust
let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
``` [1](#0-0) 

`add_fin_transfer` inserts the transfer ID into `finalised_transfers` and panics if it is already present:

```rust
fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
    require!(
        self.finalised_transfers.insert(transfer_id),
        BridgeError::TransferAlreadyFinalised.as_ref()
    );
    ...
}
``` [2](#0-1) 

This state change is committed to NEAR storage when `fin_transfer_callback` (the parent receipt) completes. All subsequent steps — `send_tokens` and `fin_transfer_send_tokens_callback` — execute as separate receipts. If they fail, the `finalised_transfers` entry is **not** rolled back.

**Step 2 — The push-payment uses `ft_transfer` for non-deployed tokens with no message.**

`send_tokens` selects `ft_transfer` (not `ft_transfer_call`) when `msg.is_empty()` and the token is not a deployed bridge token:

```rust
} else if msg.is_empty() {
    ext_token::ext(token)
        .with_attached_deposit(ONE_YOCTO)
        .with_static_gas(FT_TRANSFER_GAS)
        .ft_transfer(recipient, amount, None)
}
``` [3](#0-2) 

`ft_transfer` panics (and thus fails as a NEAR receipt) if the recipient is blacklisted, the token contract is paused, or any other token-level restriction applies.

**Step 3 — The callback never checks the `ft_transfer` promise result.**

`fin_transfer_send_tokens_callback` is chained after `send_tokens`:

```rust
self.send_tokens(token.clone(), recipient, U128(...), &msg)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(SEND_TOKENS_CALLBACK_GAS)
            .fin_transfer_send_tokens_callback(
                transfer_message, &fee_recipient, !msg.is_empty(),
                predecessor_account_id, lock_actions,
            ),
    )
``` [4](#0-3) 

The callback's only branch condition is `is_refund_required(is_ft_transfer_call)`. When `msg.is_empty()`, `is_ft_transfer_call = false`, and `is_refund_required` unconditionally returns `false` without inspecting the promise result:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) { ... }
    } else {
        // Not ft_transfer_call: don't refund
        false
    }
}
``` [5](#0-4) 

So when `ft_transfer` fails, the callback still takes the success branch: it emits `FinTransferEvent`, sends fees to the fee recipient, and returns — leaving the transfer permanently finalized with no tokens delivered.

Additionally, `unlock_tokens_if_needed` was already called (decrementing the locked-token accounting) before `send_tokens`, and the `lock_actions` revert path inside the callback is never reached:

```rust
let lock_actions = vec![self.unlock_tokens_if_needed(
    transfer_message.get_origin_chain(), &token, transfer_message.amount.0,
)];
``` [6](#0-5) 

The locked-token counter is decremented, the tokens remain physically in the bridge contract, and the accounting is permanently inconsistent.

---

### Impact Explanation

- The transfer ID is permanently in `finalised_transfers`; `fin_transfer` cannot be retried (`TransferAlreadyFinalised` panic).
- The recipient receives zero tokens.
- For non-deployed (locked) tokens, the funds remain in the bridge contract with no withdrawal mechanism.
- `FinTransferEvent` is emitted, signaling success to off-chain observers and the origin chain, while no delivery occurred.
- **Impact class**: permanent freezing of bridged funds — within the critical allowed scope.

---

### Likelihood Explanation

Any ERC-20/NEP-141 token that implements a transfer blacklist (USDC, USDT, and similar regulated stablecoins are the primary candidates) can trigger this path. The recipient address is fully attacker-controlled from the origin chain: a user can specify any NEAR account as recipient. If that account is subsequently (or already) blacklisted in the token contract on NEAR — whether by the token issuer for regulatory reasons or by a malicious actor who controls the recipient account and deliberately triggers a blacklisting — the next relayer call to `fin_transfer` will permanently freeze the funds. No admin action is required on the bridge side; the trigger is a standard token-contract feature.

---

### Recommendation

`fin_transfer_send_tokens_callback` must check the promise result for the plain `ft_transfer` path, mirroring the existing `ft_transfer_call` check. If the promise failed, the callback should:

1. Remove the transfer ID from `finalised_transfers` (un-finalize).
2. Revert lock actions via `revert_lock_actions`.
3. Emit `FailedFinTransferEvent` so the relayer and origin chain can observe the failure.

This is the pull-pattern analog recommended in the Moloch report: instead of assuming the push-payment succeeded, always verify the promise result before committing the finalized state.

---

### Proof of Concept

1. Deploy a NEP-141 token on NEAR that supports a blacklist (e.g., a USDC-equivalent).
2. Register the token with the bridge on both EVM and NEAR sides.
3. User on EVM calls `initTransfer` sending 1000 USDC to NEAR recipient `alice.near`.
4. Token issuer blacklists `alice.near` in the NEAR token contract.
5. Relayer calls `fin_transfer` with the proof.
6. `fin_transfer_callback` → `process_fin_transfer_to_near`:
   - `add_fin_transfer` inserts the transfer ID into `finalised_transfers` ✓ (committed).
   - `send_tokens` dispatches `ft_transfer(alice.near, 1000, None)`.
   - `ft_transfer` panics because `alice.near` is blacklisted.
7. `fin_transfer_send_tokens_callback` is called with a failed promise result.
   - `is_ft_transfer_call = false` → `is_refund_required` returns `false`.
   - Callback takes the success branch, emits `FinTransferEvent`.
8. `alice.near` has 0 tokens. The transfer ID is permanently finalized. Retrying `fin_transfer` panics with `TransferAlreadyFinalised`. The 1000 USDC are permanently frozen in the bridge. [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
