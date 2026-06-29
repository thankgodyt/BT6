### Title
`is_refund_required` Treats `ft_transfer_call` Failure as Success, Emitting `FinTransferEvent` When Tokens Were Never Delivered — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`is_refund_required` returns `false` (meaning "transfer succeeded, emit success event") when the underlying `ft_transfer_call` promise returns `Err` — i.e., when the token contract panics before completing the transfer. In that case, `fin_transfer_send_tokens_callback` and `resolve_utxo_fin_transfer` both emit a success event (`FinTransferEvent` / `UtxoTransferEvent`) even though the recipient never received the tokens. The transfer ID is already marked finalized and cannot be retried. The tokens remain stranded in the bridge.

---

### Finding Description

`is_refund_required` in `near/omni-bridge/src/lib.rs` is the single gate that decides whether a failed `ft_transfer_call` triggers a refund path or a success path:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    amount.0 == 0          // ← correct: refund when ft_on_transfer rejected
                } else {
                    false                  // ← BUG: non-U128 return → treated as success
                }
            }
            Err(_) => false,               // ← BUG: promise panic → treated as success
        }
    } else {
        false
    }
}
``` [1](#0-0) 

The two buggy branches are:

1. **`Err(_) => false`** — when `ft_transfer_call` itself panics (e.g., the token contract reverts before completing the transfer), the promise result is `Err`. The tokens are never moved to the recipient (state is reverted by NEAR), yet the function returns `false` ("no refund needed").

2. **`Ok(value)` + deserialization failure → `false`** — if the token contract's `ft_resolve_transfer` returns a non-`U128` value (e.g., a non-standard token), deserialization fails and the function again returns `false`.

In both cases, the callers proceed to the **success branch**:

**`fin_transfer_send_tokens_callback`** (called for standard EVM→NEAR finalization):
```rust
} else {
    // fee minting ...
    env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
}
``` [2](#0-1) 

**`resolve_utxo_fin_transfer`** (called for UTXO→NEAR finalization):
```rust
} else {
    env::log_str(
        &OmniBridgeEvent::UtxoTransferEvent { ... }.to_log_string(),
    );
    U128(0)
}
``` [3](#0-2) 

The transfer ID was already recorded as finalized by `add_fin_transfer` before `send_tokens` was called: [4](#0-3) 

And the `locked_tokens` counter was already decremented by `unlock_tokens_if_needed`: [5](#0-4) 

In the success branch, `revert_lock_actions` is **never called**, so the accounting is permanently wrong. The correct path — which does call `revert_lock_actions` and emits `FailedFinTransferEvent` — is only reached when `is_refund_required` returns `true`: [6](#0-5) 

`send_tokens` dispatches to `ft_transfer_call` for non-deployed tokens with a message, and to `mint` (which internally calls `ft_transfer_call`) for deployed tokens with a message: [7](#0-6) 

---

### Impact Explanation

When `ft_transfer_call` panics (promise `Err`):

- The token transfer is reverted by NEAR — the recipient receives nothing.
- `FinTransferEvent` / `UtxoTransferEvent` is emitted claiming the transfer succeeded.
- The transfer ID is permanently finalized — it cannot be retried.
- `locked_tokens` is decremented without a corresponding token delivery — the bridge's escrow accounting is permanently understated for that chain/token pair.
- Off-chain relayers and indexers observing `FinTransferEvent` mark the transfer complete; the user's bridged funds are permanently lost.

This matches the allowed impact scope: **loss of bridged funds** and **escrow mis-accounting**.

---

### Likelihood Explanation

Realistic triggers for `ft_transfer_call` to return `Err` (promise panic):

1. **Non-standard registered token** — a third-party token whose `ft_transfer_call` panics under certain conditions (e.g., a token with custom transfer restrictions, a fee-on-transfer token that reverts when the bridge's balance is insufficient after fee deduction, or a token that panics when the recipient is a contract).
2. **Gas exhaustion edge case** — `ft_transfer_call_gas` is computed dynamically and capped at `FT_TRANSFER_CALL_GAS`. If the gas budget is consumed by earlier operations in the same receipt, the allocated gas may be insufficient for the token contract's internal logic, causing the promise to fail.
3. **Non-standard `ft_resolve_transfer` return** — a token that returns a non-`U128` JSON value from `ft_resolve_transfer` hits the second buggy branch.

Any bridge user who initiates a transfer with a `msg` field (triggering the `ft_transfer_call` path) to a recipient whose token contract exhibits any of the above behaviors can trigger this condition.

---

### Recommendation

Treat both unexpected cases as requiring a refund (analogous to the `amount.0 == 0` case):

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                match near_sdk::serde_json::from_slice::<U128>(&value) {
                    Ok(amount) => amount.0 == 0,
                    Err(_) => true,  // unexpected return → treat as failure, refund
                }
            }
            Err(_) => true,  // promise panicked → treat as failure, refund
        }
    } else {
        false
    }
}
```

This ensures that when `ft_transfer_call` fails for any reason, `revert_lock_actions` is called, the fin-transfer record is removed (allowing retry), and `FailedFinTransferEvent` is emitted instead of `FinTransferEvent`.

---

### Proof of Concept

1. Deploy a non-standard NEP-141 token that panics inside `ft_transfer_call` when called with a non-empty `msg` (e.g., it checks `msg` and panics on unexpected content).
2. Register this token with the bridge (via the normal `deploy_token` / `bind_token` path or as a third-party token).
3. Initiate a cross-chain transfer from EVM to NEAR with a non-empty `msg` field targeting this token.
4. A relayer calls `fin_transfer` on NEAR, which calls `process_fin_transfer_to_near` → `send_tokens` → `ft_transfer_call` (panics) → `fin_transfer_send_tokens_callback`.
5. `is_refund_required` returns `false` (Err branch).
6. `FinTransferEvent` is emitted; the transfer ID is finalized; `locked_tokens` is decremented.
7. The recipient's balance is unchanged. The tokens are stranded in the bridge with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1031-1043)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
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

**File:** near/omni-bridge/src/lib.rs (L2107-2117)
```rust
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
