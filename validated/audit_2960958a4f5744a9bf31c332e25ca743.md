### Title
`is_refund_required()` Misinterprets Successful `ft_transfer_call` Return Value as Failure, Enabling Repeated nBTC Minting - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary

The `safe_mint_callback` in `satoshi-bridge` uses `is_refund_required()` to decide whether a `safe_mint` call succeeded or failed. The function treats `U128(0)` as a failure signal (account not registered). However, when `safe_mint` is called with a non-empty `msg`, it internally calls `ft_transfer_call`, whose return value is the amount **not used** (refunded) by the receiver. A receiver that keeps all tokens returns `0` from `ft_on_transfer`, causing `ft_transfer_call` — and therefore `safe_mint` — to resolve to `U128(0)`. This is the **success** case, but `is_refund_required()` treats it as failure. The UTXO is then removed from `verified_deposit_utxo`, allowing the same UTXO to be re-submitted, minting nBTC again each time.

### Finding Description

`safe_mint` in `contracts/nbtc/src/lib.rs` has two distinct code paths:

**Path A — account not registered (failure):** [1](#0-0) 
Returns `PromiseOrValue::Value(U128(0))` directly.

**Path B — account registered, `msg` is `Some` (intended success):** [2](#0-1) 
Calls `ft_transfer_call(account_id, amount, None, msg)`. Per NEP-141, `ft_transfer_call` resolves to the amount **refunded** by the receiver. A receiver that keeps all tokens returns `0` from `ft_on_transfer`, so `ft_transfer_call` resolves to `U128(0)`.

Both paths produce `U128(0)`, but they have opposite meanings.

`is_refund_required()` in `satoshi-bridge` reads the promise result and returns `true` whenever it sees `U128(0)`: [3](#0-2) 

`safe_mint_callback` uses this to decide success or failure: [4](#0-3) 

When `is_success = false` (incorrectly), the callback:
1. **Removes** the UTXO from `verified_deposit_utxo` (line 439–441), releasing it for re-submission.
2. Fires a detached `burn(bridge_id, mint_amount, ...)` — but the bridge's balance is already 0 (the tokens were transferred to the receiver by `ft_transfer_call`), so this burn **panics silently**.
3. Refunds the relayer's NEAR deposit.

The receiver already holds `mint_amount` nBTC. Because the UTXO key was removed from `verified_deposit_utxo`, the same UTXO can be re-submitted via `safe_verify_deposit`. Each re-submission mints another `mint_amount` nBTC to the receiver.

The retry mechanism is confirmed by the test comment: [5](#0-4) 

### Impact Explanation

Every `safe_verify_deposit` call where the recipient is a contract whose `ft_on_transfer` returns `0` (the standard NEP-141 "keep all tokens" response) is misclassified as a failure. The UTXO is released, and the same BTC deposit can be re-submitted repeatedly, minting unbacked nBTC each time. This is **unauthorized minting** of the bridge's pegged asset.

The OmniBridge integration is the primary intended consumer of `safe_verify_deposit` with a non-empty `msg`. OmniBridge's `ft_on_transfer` returns `0` by design (it keeps all tokens). Therefore this bug affects the primary integration path systematically.

### Likelihood Explanation

The `safe_verify_deposit` path with a non-empty `msg` is the documented OmniBridge integration flow: [6](#0-5) 

Any deposit routed through OmniBridge (recipient = OmniBridge contract, `msg` = non-empty routing message) triggers the bug on every submission. A relayer that automatically retries failed deposits would re-mint tokens on each retry. An attacker who deploys a contract returning `0` from `ft_on_transfer` and controls or influences a relayer can exploit this directly.

### Recommendation

`safe_mint` must unambiguously signal success vs. failure to its caller. Options:

1. **Separate return values**: When `safe_mint` calls `ft_transfer_call`, wrap the result so that `U128(0)` from `ft_transfer_call` (receiver kept tokens = success) is distinguishable from the direct `U128(0)` return (account not registered = failure). For example, return a sentinel value (e.g., `U128(u128::MAX)`) for the unregistered-account failure case.

2. **Avoid `ft_transfer_call` in `safe_mint`**: Mint directly to the recipient and let the caller handle the downstream `ft_transfer_call` separately, so the success/failure signal is unambiguous.

3. **Check bridge balance before burn**: In `safe_mint_callback`, verify the bridge has sufficient balance before calling `burn`, and treat a zero bridge balance as evidence that `ft_transfer_call` succeeded (tokens were transferred out).

### Proof of Concept

1. Attacker deploys contract `attacker.near` implementing `ft_on_transfer` that returns `"0"` (keeps all tokens).
2. Attacker calls `get_user_deposit_address` with `DepositMsg { recipient_id: "attacker.near", safe_deposit: Some(SafeDepositMsg { msg: "{}" }), ... }`.
3. Attacker sends BTC to the derived deposit address.
4. Relayer calls `safe_verify_deposit` with the BTC proof.
5. `verify_safe_deposit_callback` inserts UTXO into `verified_deposit_utxo`, calls `safe_mint("attacker.near", amount, Some("{}"))`.
6. `safe_mint` deposits `amount` to bridge, calls `ft_transfer_call("attacker.near", amount, None, "{}")`.
7. `attacker.near::ft_on_transfer` returns `"0"` → `ft_transfer_call` resolves to `U128(0)`.
8. `is_refund_required()` sees `U128(0)` → returns `true`.
9. `safe_mint_callback`: `is_success = false` → removes UTXO from `verified_deposit_utxo`, fires detached `burn` (panics silently, bridge balance = 0).
10. `attacker.near` now holds `amount` nBTC. UTXO is no longer in `verified_deposit_utxo`.
11. Relayer (or attacker acting as relayer) re-submits `safe_verify_deposit` for the same UTXO.
12. Steps 5–10 repeat. `attacker.near` accumulates `amount` nBTC per iteration, unbacked by BTC.

### Citations

**File:** contracts/nbtc/src/lib.rs (L114-116)
```rust
        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/nbtc/src/lib.rs (L118-120)
```rust
        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L427-456)
```rust
    ) -> bool {
        let is_success = !is_refund_required();
        let relayer_account_id = env::signer_account_id();

        if is_success {
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128(pending_utxo_info.utxo.balance.into())]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);

            ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
                .with_static_gas(GAS_FOR_BURN_CALL)
                .burn(
                    env::current_account_id(),
                    mint_amount,
                    relayer_account_id,
                    U128(0),
                )
                .detach();

            Promise::new(env::signer_account_id())
                .transfer(self.required_balance_for_safe_deposit())
                .detach();
        }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L474-489)
```rust
fn is_refund_required() -> bool {
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
}
```

**File:** contracts/satoshi-bridge/tests/test_satoshi_bridge.rs (L3221-3223)
```rust
    // The UTXO key was released from verified_deposit_utxo, so the same
    // deposit can be retried once alice registers.
    check!(context.storage_deposit("nbtc", "alice"));
```

**File:** CLAUDE.md (L107-114)
```markdown
**safe_verify_deposit (integration):**
- Primarily used by Omni Bridge
- NO fees charged
- User must attach NEAR for storage (via `#[payable]`)
- **Reverts entire transaction if mint fails** (no lost & found)
- Requires `safe_deposit: Some(SafeDepositMsg)` in DepositMsg
- **post_actions must be None** (not supported in safe mode)
- Safer for integrations - atomic success/failure
```
