### Title
Unrestricted `sign_btc_transaction` with Attacker-Controlled `key_version` Allows Permanent Corruption of Any Pending Withdrawal PSBT - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

---

### Summary

`sign_btc_transaction` is a public, permissionless function that accepts a caller-controlled `key_version` parameter. It performs no ownership check against the pending transaction's `account_id`. Any unprivileged NEAR account can call it on a victim's pending withdrawal with an arbitrary `key_version`, causing the MPC to sign with a mismatched key. The resulting invalid signature is stored and cannot be overwritten (the "Already signed" guard fires on any retry), permanently corrupting the PSBT and locking the victim's withdrawal in an unbroadcastable state that requires operator intervention to cancel.

---

### Finding Description

`sign_btc_transaction` in `contracts/satoshi-bridge/src/api/chain_signatures.rs` carries only a `#[pause]` guard — no role check and no assertion that `env::predecessor_account_id()` matches `btc_pending_info.account_id`:

```rust
// api/chain_signatures.rs lines 21-43
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,          // ← fully attacker-controlled
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();
    // ← no check: env::predecessor_account_id() == btc_pending_info.account_id
    ...
    self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
        .into()
}
``` [1](#0-0) 

The attacker-supplied `key_version` is forwarded verbatim to the MPC `sign` call in `internal_sign_btc_transaction`:

```rust
// chain_signature.rs lines 99-103
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← attacker value reaches MPC
})
``` [2](#0-1) 

In `sign_btc_transaction_callback`, the MPC response is stored unconditionally after a single idempotency guard:

```rust
// chain_signature.rs lines 154-158
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
btc_pending_info.signatures[sign_index] = Some(signature.clone());
``` [3](#0-2) 

No verification is performed that the stored signature is valid for the public key derived from `path`. Once the slot is filled, no further signing attempt for that index is possible — the "Already signed" guard permanently blocks it.

When all slots are filled, `is_all_signed()` triggers, the PSBT is assembled with the corrupted signature, and the pending info transitions to `PendingVerify` stage with `tx_bytes_with_sign` set to an unbroadcastable transaction:

```rust
// chain_signature.rs lines 171-195
if btc_pending_info.is_all_signed() {
    let tx_bytes_with_sign = psbt.extract_tx_bytes_with_sign();
    ...
    btc_pending_info.tx_bytes_with_sign = Some(tx_bytes_with_sign);
    btc_pending_info.to_pending_verify_stage();
``` [4](#0-3) 

---

### Impact Explanation

The victim's withdrawal is stuck in `PendingVerify` with a Bitcoin transaction that will be rejected by the network (invalid witness/signature). The UTXOs consumed by the PSBT remain in `unavailable_utxos` and cannot be reused. Recovery requires a privileged operator to call `cancel_withdraw`, which triggers an RBF cancellation flow and eventually refunds the user's nBTC via `lost_found`. Until operator intervention, the user's funds are inaccessible and the bridge's UTXO pool is partially depleted. This matches the **Medium** impact class: stuck bridge state requiring operator intervention.

---

### Likelihood Explanation

The attack requires no special role, no tokens, and no prior relationship with the victim. The attacker only needs to know a valid `btc_pending_sign_id` (emitted publicly via `Event::GenerateBtcPendingInfo`) and to call `sign_btc_transaction` before the legitimate relayer does. Because signing is a multi-step process (one call per input), the race window is wide. Any unprivileged NEAR account can execute this against any pending withdrawal at any time the bridge is unpaused.

---

### Recommendation

1. **Add an ownership check**: At the top of `sign_btc_transaction`, assert `env::predecessor_account_id() == btc_pending_info.account_id` (or require a trusted relayer role, consistent with the rest of the bridge API).
2. **Validate `key_version`**: Reject any `key_version` that does not match the value stored in config or the pending info, rather than accepting it as a free parameter from the caller.
3. **Verify the signature before storing**: In `sign_btc_transaction_callback`, verify the returned ECDSA signature against the derived public key before writing it into the PSBT slot, so a mismatched-key response is discarded rather than permanently stored.

---

### Proof of Concept

1. Alice calls `ft_transfer_call` → bridge creates `BTCPendingInfo` with id `"abc123"`, emits `GenerateBtcPendingInfo { btc_pending_id: "abc123" }`.
2. Attacker observes the event and immediately calls:
   ```
   sign_btc_transaction("abc123", 0, 9999)
   ```
   with `key_version = 9999` (a non-existent or wrong version).
3. The MPC signs `payload` under key version 9999, returning a signature for a different public key.
4. `sign_btc_transaction_callback` stores the invalid signature; `signatures[0]` is now `Some(bad_sig)`.
5. Any subsequent legitimate call to `sign_btc_transaction("abc123", 0, correct_version)` panics with `"Already signed"`.
6. If the PSBT has only one input, `is_all_signed()` is immediately true; the bridge assembles and stores an unbroadcastable `tx_bytes_with_sign` and moves to `PendingVerify`.
7. Alice's withdrawal is permanently stuck until an operator calls `cancel_withdraw("abc123", ...)`.

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-43)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L95-103)
```rust
        let payload = btc_pending_info
            .get_psbt()
            .get_hash_to_sign(sign_index, &public_keys);
        let path = btc_pending_info.vutxos[sign_index].get_path();
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L154-158)
```rust
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L171-195)
```rust
            if btc_pending_info.is_all_signed() {
                let tx_bytes_with_sign = psbt.extract_tx_bytes_with_sign();

                // For ZCash chains, use base64 encoding to save space (1.33x vs 2x overhead for hex)
                // ZCash transactions with Orchard bundles are larger and benefit from compact encoding
                // For Bitcoin chains, keep hex encoding for backward compatibility

                #[cfg(feature = "zcash")]
                let tx_bytes_base64 = {
                    use near_sdk::base64::{engine::general_purpose::STANDARD, Engine};
                    STANDARD.encode(&tx_bytes_with_sign)
                };

                Event::SignedBtcTransaction {
                    account_id: &account_id,
                    tx_id: btc_pending_sign_id.clone(),
                    #[cfg(not(feature = "zcash"))]
                    tx_bytes: &tx_bytes_with_sign,
                    #[cfg(feature = "zcash")]
                    tx_bytes_base64,
                }
                .emit();

                btc_pending_info.tx_bytes_with_sign = Some(tx_bytes_with_sign);
                btc_pending_info.to_pending_verify_stage();
```
