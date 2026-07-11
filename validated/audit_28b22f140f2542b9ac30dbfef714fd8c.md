### Title
Missing Caller-Ownership Check in `sign_btc_transaction` Allows Attacker to Corrupt Any User's Pending Signing State with Attacker-Controlled `key_version` — (`contracts/satoshi-bridge/src/api/chain_signatures.rs`, `contracts/satoshi-bridge/src/chain_signature.rs`)

---

### Summary

The public `sign_btc_transaction` entry point performs no check that `env::predecessor_account_id()` matches the `account_id` stored inside the `BTCPendingInfo` record. Any unprivileged caller can therefore invoke it against any other user's `btc_pending_sign_id`. Combined with the fully attacker-controlled `key_version` parameter — which is forwarded verbatim to the chain-signatures MPC contract — an attacker can inject a signature produced under a different key version into the victim's PSBT. If the chain-signatures contract accepts the wrong version, the stored signature is cryptographically invalid for the UTXO's controlling key, the PSBT is finalized with that bad signature, the pending record transitions to `PendingVerify`, and the victim's BTC withdrawal is permanently stuck.

---

### Finding Description

**Entry point — `sign_btc_transaction` (api/chain_signatures.rs lines 21-43)**

```rust
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,          // ← fully attacker-controlled
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();   // only checks stage, not ownership
    // ... no predecessor_account_id == btc_pending_info.account_id check ...
    self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
        .into()
}
``` [1](#0-0) 

There is no `predecessor_account_id` call anywhere in this file (confirmed by grep). `assert_pending_sign` only validates the state-machine stage, not the caller identity. [2](#0-1) 

**Signing call — `internal_sign_btc_transaction` (chain_signature.rs lines 76-113)**

`path` and `payload` are derived from the stored `BTCPendingInfo` (correct for the victim), but `key_version` is passed through unchanged from the attacker:

```rust
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← attacker's value
})
``` [3](#0-2) 

**Callback — `sign_btc_transaction_callback` (chain_signature.rs lines 135-213)**

The callback re-derives the public key from the stored path (correct key), but stores the returned signature without verifying it against that public key:

```rust
btc_pending_info.signatures[sign_index] = Some(signature.clone());
``` [4](#0-3) 

Once stored, the slot is permanently locked — the `is_none()` guard prevents any re-signing: [5](#0-4) 

When `is_all_signed()` returns true, the PSBT is extracted and the record transitions to `PendingVerify`, removing it from `btc_pending_sign_ids`: [6](#0-5) 

The victim's nBTC was already burned at withdrawal initiation; the BTC is now locked in the bridge's UTXOs with no recovery path visible in the scoped production code.

---

### Impact Explanation

If the chain-signatures MPC contract accepts a non-zero `key_version` (i.e., it does not hard-reject unknown versions), the signature returned is valid for a different key than the one controlling the UTXO. The resulting Bitcoin transaction is cryptographically invalid and will be rejected by the Bitcoin network. Because the NEAR-side state has already advanced to `PendingVerify` and the sign-slot is marked occupied, the victim cannot re-sign. The BTC is permanently locked in the bridge's UTXOs while the user's nBTC has already been burned — a critical, irreversible loss of user funds.

Even if the chain-signatures contract rejects the wrong `key_version` (callback returns `false`, no signature stored), the ownership bypass itself is a confirmed invariant violation: any user can advance any other user's economic signing surface.

---

### Likelihood Explanation

- The `btc_pending_sign_id` is a SHA-256 hash of PSBT payload preimages, emitted in on-chain events (`Event::BtcInputSignature`, `Event::SignedBtcTransaction`), making it publicly observable.
- The call requires only an attached NEAR deposit (paid by the attacker, forwarded to chain signatures).
- No privileged role is required.
- The attacker only needs to know the victim's pending ID and submit the call before the victim completes signing.

---

### Recommendation

Add a caller-ownership guard at the top of `sign_btc_transaction`:

```rust
let caller = env::predecessor_account_id();
require!(
    caller == btc_pending_info.account_id,
    "Unauthorized: caller is not the owner of this pending transaction"
);
```

Additionally, validate `key_version` against a contract-configured expected version before forwarding it to the chain-signatures contract, or derive it from the stored UTXO metadata rather than accepting it from the caller.

---

### Proof of Concept

1. Victim calls `withdraw` → bridge creates `BTCPendingInfo` with `account_id = victim`, `btc_pending_sign_id = "abc123"`, 2 inputs, burns victim's nBTC.
2. Victim signs input 0 with correct `key_version = 0`.
3. Attacker observes `"abc123"` from on-chain events.
4. Attacker calls `sign_btc_transaction("abc123", 1, 999)` with `key_version = 999`.
5. Bridge forwards `SignRequest { payload: <victim's input-1 hash>, path: <victim's path>, key_version: 999 }` to chain-signatures MPC.
6. MPC returns a signature under key version 999 (a different key than the UTXO's controlling key).
7. Callback stores the invalid signature; `is_all_signed()` → true.
8. `psbt.extract_tx_bytes_with_sign()` produces an invalid Bitcoin transaction.
9. State transitions to `PendingVerify`; `btc_pending_sign_ids` entry removed.
10. Bitcoin network rejects the transaction. Victim's BTC is permanently locked; nBTC already burned.

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L21-43)
```rust
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L129-132)
```rust
impl BTCPendingInfo {
    pub fn assert_pending_sign(&self) {
        self.state.assert_pending_sign();
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L99-112)
```rust
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK)
                .sign_btc_transaction_callback(
                    btc_pending_info.account_id.clone(),
                    btc_pending_sign_id,
                    sign_index,
                ),
        )
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L154-158)
```rust
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L171-207)
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

                let is_original_tx = btc_pending_info.get_original_tx_id().is_none();
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
                if is_original_tx {
                    account
                        .btc_pending_verify_list
                        .insert(btc_pending_sign_id.clone());
                }
```
