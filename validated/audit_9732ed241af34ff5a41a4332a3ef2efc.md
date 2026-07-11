Based on the code retrieved, I can identify a valid analog to the CLGauge "funds sent to contract instead of recipient" vulnerability class.

---

### Title
`safe_mint` Permanently Mints nBTC to Bridge Contract Instead of User When Recipient Account Is Unregistered — (`contracts/nbtc/src/lib.rs`)

### Summary

In the `safe_verify_deposit` (OmniBridge) flow, when the intended recipient has not registered their account in the nBTC token contract, `safe_mint` silently mints the full deposit amount to the bridge contract itself (`bridge_id`) and returns `U128(0)` without panicking. The satoshi-bridge callback interprets this as a successful mint, marks the UTXO as verified, and the user's BTC is permanently consumed with zero nBTC received.

### Finding Description

The `safe_mint` function in `contracts/nbtc/src/lib.rs` first unconditionally deposits the full `amount` into `bridge_id`'s balance via `internal_deposit`, then checks whether the recipient account is registered:

```rust
pub fn safe_mint(
    &mut self,
    account_id: AccountId,
    amount: U128,
    msg: Option<String>,
) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(
        account_id != self.bridge_id,
        "safe_mint: account_id must not be the bridge"
    );
    self.token.internal_deposit(&self.bridge_id, amount.into()); // tokens credited to bridge

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0)); // silent early return, tokens stay in bridge
    }
    // only reaches ft_transfer_call if account IS registered
    if let Some(msg) = msg {
        self.ft_transfer_call(account_id, amount, None, msg)
    } else {
        self.ft_transfer(account_id, amount, None);
        PromiseOrValue::Value(amount)
    }
}
``` [1](#0-0) 

When `account_id` is not registered, the function:
1. Mints `amount` tokens into `bridge_id` (the bridge contract itself).
2. Returns `PromiseOrValue::Value(U128(0))` — no panic, no transfer to the user.

The satoshi-bridge's `safe_mint_callback` (at `contracts/satoshi-bridge/src/btc_light_client/deposit.rs:214`) uses `is_promise_success()` to determine whether to finalize the deposit. Because `safe_mint` returns gracefully (no panic), `is_promise_success()` evaluates to `true`. The callback therefore marks the UTXO as verified and adds it to the bridge's UTXO set — exactly as it would for a successful mint. [2](#0-1) 

The parallel in the regular `mint` path confirms the callback pattern: `mint_callback` uses `is_promise_success()` as the sole success gate, with no inspection of the returned token amount. [3](#0-2) 

The deposit UTXO is then stored permanently: [4](#0-3) 

After this point, the UTXO is in `verified_deposit_utxo`, so `request_refund` for the same UTXO will be rejected ("UTXO already verified via deposit"). The user cannot recover their BTC.

### Impact Explanation

**Critical — Permanent loss of user funds.**

The user's BTC deposit is irreversibly consumed: the UTXO is marked as verified and cannot be refunded. The minted nBTC tokens are credited to the bridge contract (`bridge_id`) with no on-chain mechanism to redistribute them to the rightful owner. The bridge's total supply increases while the user holds nothing, breaking the 1:1 BTC-to-nBTC backing invariant for that user.

### Likelihood Explanation

**Medium-High.**

Any user who initiates a `safe_verify_deposit` (OmniBridge path, i.e., `safe_deposit: Some({msg})`) without having previously called `storage_deposit` on the nBTC token contract will trigger this path. NEAR NEP-141 requires explicit account registration; new users or users interacting via integrations that omit the registration step are directly exposed. The bridge itself performs no pre-flight check that the recipient is registered before accepting the BTC deposit or before calling `safe_mint`.

### Recommendation

Add a registration guard in `safe_mint` **before** calling `internal_deposit`, or change the deposit order so tokens are only minted after confirming the recipient is registered:

```diff
 pub fn safe_mint(...) -> PromiseOrValue<U128> {
     self.assert_bridge();
     require!(account_id != self.bridge_id, "...");
+    require!(
+        self.token.accounts.get(&account_id).is_some(),
+        "safe_mint: recipient account is not registered"
+    );
     self.token.internal_deposit(&self.bridge_id, amount.into());
     ...
 }
```

Alternatively, the satoshi-bridge's `safe_mint_callback` should inspect the returned `U128` value: if it is `0` and the mint amount was non-zero, treat the call as a failure and remove the UTXO from `verified_deposit_utxo` so a refund remains possible.

### Proof of Concept

1. Alice generates a deposit address via `get_user_deposit_address` with `safe_deposit: Some({msg: "..."})` and `recipient_id: "alice.near"`.
2. Alice sends 100,000 sat to the derived BTC address. The transaction is confirmed.
3. Alice has **not** called `storage_deposit` on the nBTC contract, so `alice.near` is unregistered.
4. The relayer calls `safe_verify_deposit(deposit_msg, tx_bytes, vout, proof)`.
5. The bridge verifies the proof and calls `nbtc.safe_mint("alice.near", 100000, Some(msg))`.
6. Inside `safe_mint`: `internal_deposit(&bridge_id, 100000)` executes — bridge now holds 100,000 nBTC.
7. `self.token.accounts.get(&"alice.near")` returns `None` → function returns `U128(0)` without panicking.
8. `safe_mint_callback` sees `is_promise_success() == true`, marks the UTXO as verified, stores it.
9. Alice calls `request_refund` → rejected: "UTXO already verified via deposit".
10. Alice holds 0 nBTC. Her 100,000 sat BTC is permanently lost. The bridge holds 100,000 extra nBTC with no corresponding user balance.

### Citations

**File:** contracts/nbtc/src/lib.rs (L101-124)
```rust
    pub fn safe_mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }

        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.ft_transfer(account_id, amount, None);
            PromiseOrValue::Value(amount)
        }
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L43-84)
```rust
#[near]
impl Contract {
    #[private]
    pub fn mint_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_fee: U128,
        pending_utxo_info: PendingUTXOInfo,
    ) -> bool {
        let is_success = is_promise_success();
        if is_success {
            if !self.check_account_exists(&recipient_id) {
                self.internal_set_account(&recipient_id, Account::new(&recipient_id));
            }
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128::from(u128::from(pending_utxo_info.utxo.balance))]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);
        }
        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee,
            relayer_account_id: env::signer_account_id(),
            relayer_fee,
            success: is_success,
        }
        .emit();
        is_success
    }
```
