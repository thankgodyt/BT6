### Title
Partial `ft_on_transfer` Rejection Bypasses Refund Logic, Causing Permanent Token Loss and Fee Mis-accounting — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`is_refund_required` only triggers a revert when the `ft_transfer_call` used-amount equals **zero** (complete rejection). When a recipient contract's `ft_on_transfer` returns a **partial** refund (used-amount > 0 but < `amount_without_fee`), the function returns `false`, the success branch executes, the fee is paid to `fee_recipient`, and the partially-refunded tokens are left stranded in the bridge with no burn or re-lock — permanently breaking the cross-chain accounting invariant.

---

### Finding Description

**Call chain:**

`fin_transfer` → `fin_transfer_callback` → `process_fin_transfer_to_near` → `send_tokens` → `fin_transfer_send_tokens_callback`

When `transfer_message.msg` is non-empty, `send_tokens` issues either:

- **Deployed token:** `mint(recipient, amount_without_fee, Some(msg))` — which internally mints tokens to the bridge contract itself, then calls `ft_transfer_call(recipient, amount, None, msg)` on the token contract.
- **Native token:** `ft_transfer_call(recipient, amount_without_fee, None, msg)` directly. [1](#0-0) 

For deployed tokens, `mint` with a `msg` deposits tokens to `predecessor_account_id` (the bridge) and then calls `ft_transfer_call`: [2](#0-1) 

The promise result seen by `fin_transfer_send_tokens_callback` is the **used amount** returned by `ft_transfer_call` (per NEP-141: `original_amount − refund_amount`).

`is_refund_required` then checks:

```rust
amount.0 == 0   // only triggers revert on COMPLETE rejection
``` [3](#0-2) 

If the recipient's `ft_on_transfer` returns a **partial** refund (e.g., 50 out of 100), the used-amount is 50, `amount.0 == 0` is `false`, and `is_refund_required` returns `false`. The `else` branch executes unconditionally: [4](#0-3) 

This means:
1. The fee is minted/transferred to `fee_recipient` as if the full transfer succeeded.
2. `burn_tokens_if_needed` is **not** called on the refunded portion.
3. `revert_lock_actions` is **not** called — `locked_tokens` remains decremented by the full `amount` even though 50% was returned.
4. `FinTransferEvent` is emitted (success), permanently marking the transfer as finalised.

The token contract's `ft_resolve_transfer` refunds the 50 tokens back to the bridge's own balance, but the bridge has no mechanism to handle them: they are not burned (for deployed tokens) and not re-locked (for native tokens).

---

### Impact Explanation

**Deployed tokens (bridge-minted):**
- Bridge mints 100 tokens to itself, sends via `ft_transfer_call`.
- Recipient accepts 50; `ft_resolve_transfer` returns 50 to bridge.
- Bridge holds 50 deployed tokens permanently — they are never burned.
- Source-chain tokens remain locked/burned.
- Result: 50 tokens of supply exist on NEAR with no corresponding backing on the source chain. The user permanently loses 50 tokens.

**Native tokens (locked in bridge):**
- Bridge calls `ft_transfer_call` for 100 tokens.
- 50 are refunded back to bridge's balance.
- `locked_tokens` was decremented by 100 (full amount) in `unlock_tokens_if_needed` at line 1881–1885, but only 50 were actually delivered.
- The 50 refunded tokens sit in bridge's balance untracked, and `locked_tokens` is permanently understated by 50. [5](#0-4) 

**Fee mis-accounting:**
- The fee is paid to `fee_recipient` even though the recipient only received a fraction of the intended tokens.
- For native tokens, the fee is paid from the bridge's token balance (line 1731), which now also contains the 50 refunded tokens — the accounting is entirely broken. [6](#0-5) 

---

### Likelihood Explanation

The `msg` field is set by the **original sender** on the source chain (embedded in the on-chain proof). Any sender who bridges to a NEAR DeFi contract (DEX, lending protocol, vault) that uses `ft_on_transfer` to conditionally accept tokens (e.g., slippage checks, capacity limits) can trigger this. The relayer simply relays the proof; no relayer compromise is needed. The path is fully reachable through the standard `fin_transfer` production flow.

---

### Recommendation

`is_refund_required` must treat **any** used-amount strictly less than `amount_without_fee` as a partial failure requiring revert. The check should be:

```rust
// Instead of: amount.0 == 0
amount.0 < amount_without_fee   // refund required if not fully accepted
```

Alternatively, the callback should read the used-amount and handle three cases:
- `used == amount_without_fee`: full success → pay fee, log success.
- `used == 0`: full rejection → burn/re-lock full amount, log failure.
- `0 < used < amount_without_fee`: partial rejection → burn/re-lock the refunded portion, pay fee proportionally or not at all, log partial failure.

---

### Proof of Concept

1. Deploy a NEAR contract (`partial-reject`) whose `ft_on_transfer` always returns `U128(amount / 2)` (refunds 50%).
2. On the source chain, initiate a transfer of 100 tokens with `fee=1`, `msg="swap"` (non-empty), recipient = `partial-reject.near`.
3. Relayer submits `fin_transfer` with valid proof.
4. `process_fin_transfer_to_near` calls `send_tokens(..., "swap")` → `ft_transfer_call(partial-reject.near, 99, None, "swap")`.
5. `partial-reject.near::ft_on_transfer` returns `U128(49)` (refund 49 of 99).
6. Token's `ft_resolve_transfer` refunds 49 tokens back to bridge.
7. `ft_transfer_call` resolves with used-amount = 50.
8. `fin_transfer_send_tokens_callback` is called; `is_refund_required` returns `false` (50 ≠ 0).
9. Fee (1 token) is minted/transferred to `fee_recipient`. ✓ (fee paid)
10. `FinTransferEvent` is emitted. ✓ (marked success)
11. Assert: `partial-reject.near` holds 50 tokens. `fee_recipient` holds 1 token. Bridge holds 49 tokens (stuck, not burned). Source chain: 100 tokens locked. **49 tokens are permanently lost.** [7](#0-6) [8](#0-7)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L2082-2117)
```rust
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

**File:** near/omni-token/src/lib.rs (L127-144)
```rust
    fn mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_controller();

        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
    }
```
