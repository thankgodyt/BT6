### Title
Inverted Refund Condition in `is_refund_required` Causes Escrow Mis-Accounting and Token Supply Inflation — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

`is_refund_required` uses `amount.0 == 0` to decide whether a refund is needed after an `ft_transfer_call`. Under NEAR's NEP-141 standard, `ft_on_transfer` returning `0` means the receiver **accepted all tokens** (no refund). The condition is inverted: every successful delivery triggers the failure path, and every failed delivery triggers the success path.

---

### Finding Description

`is_refund_required` reads the promise result of the recipient's `ft_on_transfer` and returns `true` when `amount.0 == 0`:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    // Normal case: refund if the used token amount is zero
                    amount.0 == 0   // ← INVERTED
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    } else {
        false
    }
}
``` [1](#0-0) 

Under NEP-141, the return value of `ft_on_transfer` is the **amount to refund** (unused tokens):

| `ft_on_transfer` return | NEP-141 meaning | `is_refund_required` result | Correct result |
|---|---|---|---|
| `0` | All tokens accepted — no refund | `true` (refund!) | `false` |
| `N > 0` | N tokens rejected — refund N | `false` (no refund) | `true` |

This function is called in two critical paths:

**Path 1 — `fin_transfer_send_tokens_callback`** (inbound bridge finalization):

```rust
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(...);   // silently fails — bridge holds no tokens
    self.revert_lock_actions(&lock_actions);  // re-locks already-released tokens
    self.remove_fin_transfer(...);
    // emits FailedFinTransferEvent
} else {
    // sends fee, emits FinTransferEvent
}
``` [2](#0-1) 

**Path 2 — `resolve_fast_transfer`** (fast-transfer relayer settlement):

```rust
self.burn_tokens_if_needed(token_id.clone(), amount);
if Self::is_refund_required(is_ft_transfer_call) {
    self.remove_fast_transfer(fast_transfer_id);
    amount   // returns full amount as refund
} else {
    U128(0)
}
``` [3](#0-2) 

The test suite confirms the inverted behavior is present: it sets up `U128(0)` as the promise result and asserts that locked tokens are **restored** (failure path taken), which is the wrong outcome for a successful delivery: [4](#0-3) 

---

### Impact Explanation

**For `fin_transfer_send_tokens_callback` (inbound finalization with message):**

- **Deployed (bridge) tokens**: Tokens are minted to the recipient via `ft_transfer_call`. The recipient's `ft_on_transfer` returns `0` (success). The bridge incorrectly enters the failure path, calls `burn_tokens_if_needed` (which silently fails because the bridge holds no tokens), and emits `FailedFinTransferEvent`. The recipient retains the minted tokens while the bridge records the transfer as failed — **permanent token supply inflation**.

- **Native (locked) tokens**: Tokens are unlocked and transferred to the recipient. The bridge then calls `revert_lock_actions`, re-incrementing `locked_tokens` even though the tokens have already left the escrow. The bridge's locked-token ledger is inflated, allowing future `fin_transfer` calls to succeed against a phantom balance — **escrow mis-accounting enabling future unauthorized releases**.

**For `resolve_fast_transfer`:**

When a relayer's `ft_on_transfer` returns `0` (accepted), the bridge returns the full `amount` from the callback, causing the token contract to attempt to claw back tokens from the relayer. The relayer's fast-transfer settlement is silently broken.

---

### Likelihood Explanation

The bug fires on **every** `fin_transfer` that includes a non-empty `msg` field (triggering `ft_transfer_call` instead of plain `ft_transfer`), whenever the recipient contract correctly returns `0` from `ft_on_transfer`. This is the standard NEP-141 success response. No special attacker action is required — normal bridge usage with any message-bearing transfer is sufficient.

---

### Recommendation

Invert the condition in `is_refund_required`:

```rust
// Before (wrong):
amount.0 == 0

// After (correct):
amount.0 != 0
```

A non-zero return from `ft_on_transfer` means unused tokens exist and a refund is warranted. Zero means full acceptance and no refund is needed.

---

### Proof of Concept

1. A relayer submits a valid MPC-signed `fin_transfer` proof for a deployed bridge token with a non-empty `msg` (e.g., a DeFi integration message).
2. The bridge calls `ft_transfer_call(recipient, amount, msg)` on the token contract, minting `amount` tokens to the recipient.
3. The recipient's `ft_on_transfer` returns `"0"` — the standard NEP-141 success response.
4. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = true` and promise result `U128(0)`.
5. `is_refund_required` evaluates `0 == 0 → true`, entering the failure branch.
6. `burn_tokens_if_needed` is called but silently fails (bridge holds no tokens).
7. `remove_fin_transfer` removes the nonce record; `FailedFinTransferEvent` is emitted.
8. **Result**: The recipient holds the minted tokens; the bridge's supply accounting records no corresponding burn. Repeating this across multiple transfers inflates the deployed token supply unboundedly, eventually allowing the bridge to mint tokens against non-existent origin-chain collateral.

### Citations

**File:** near/omni-bridge/src/lib.rs (L902-912)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1048-1072)
```rust
        match env::promise_result_checked(0, usize::MAX) {
            Ok(_) => Promise::new(recipient).transfer(amount),
            Err(_) => env::panic_str(BridgeError::NearWithdrawFailed.to_string().as_str()),
        }
    }

    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
    }

    #[private]
    #[payable]
    pub fn claim_fee_callback(
        &mut self,
        #[serializer(borsh)] predecessor_account_id: &AccountId,
        #[callback_result]
        #[serializer(borsh)]
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
