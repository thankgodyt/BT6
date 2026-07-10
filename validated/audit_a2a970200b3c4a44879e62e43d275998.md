### Title
Unvalidated `key_version` in `sign_btc_transaction` Allows Any Caller to Inject an Invalid MPC Signature, Temporarily Locking Withdrawal Funds — (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

`sign_btc_transaction` carries no access control and accepts an attacker-supplied `key_version` that is forwarded verbatim to the MPC service. The callback stores whatever signature the MPC service returns without verifying it against the expected public key. Once stored, the slot is permanently closed to overwrite. An attacker who races the legitimate relayer can inject a signature produced under the wrong key, causing the finalized Bitcoin transaction to be cryptographically invalid and the user's withdrawal to be stuck until an RBF recovery is performed — which the attacker can immediately repeat.

---

### Finding Description

**No access control on `sign_btc_transaction`.**

`verify_deposit_v2` and the entire deposit/withdraw-verify surface are gated by `#[trusted_relayer]`. `sign_btc_transaction` is not:

```
// api/chain_signatures.rs lines 19-26
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,          // ← fully attacker-controlled
) -> PromiseOrValue<bool>
```

Any NEAR account can call this for any existing `btc_pending_sign_id`.

**`key_version` is forwarded to the MPC service without validation.**

`internal_sign_btc_transaction` passes the caller-supplied value directly:

```
// chain_signature.rs lines 99-103
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← attacker value reaches MPC
})
```

The NEAR chain-signatures MPC service uses `key_version` to select a different key-derivation branch. A non-zero `key_version` causes the MPC service to sign with a key that is *different* from the key the bridge derived the deposit address from.

**The callback derives the expected public key from the path alone (ignoring `key_version`) and stores the signature without cross-checking.**

```
// chain_signature.rs lines 145-158
let public_key = self
    .generate_btc_public_key(
        &self.internal_unwrap_btc_pending_info(&btc_pending_sign_id)
            .vutxos[sign_index]
            .get_path(),
    )
    .inner;                                    // ← key_version=0 implicitly
let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
btc_pending_info.signatures[sign_index] = Some(signature.clone()); // ← stored, no key check
```

The `require!(is_none())` guard means the slot is permanently closed once written. The legitimate relayer can never overwrite the attacker's invalid signature.

**The PSBT is finalized with the invalid signature and the state advances to `PendingVerify`.**

```
// chain_signature.rs lines 167-195
let mut psbt = btc_pending_info.get_psbt();
psbt.save_signature(sign_index, signature, public_key);
btc_pending_info.psbt_hex = psbt.serialize();
if btc_pending_info.is_all_signed() {
    let tx_bytes_with_sign = psbt.extract_tx_bytes_with_sign();
    // ...
    btc_pending_info.tx_bytes_with_sign = Some(tx_bytes_with_sign);
    btc_pending_info.to_pending_verify_stage();
```

The PSBT standard (BIP-174) stores signatures as opaque bytes; `save_signature` and `extract_tx_bytes_with_sign` do not validate the signature against the public key. The resulting serialized transaction carries a signature that does not satisfy the script, so it will be rejected by every Bitcoin node.

---

### Impact Explanation

The user's withdrawal is stuck in `PendingVerify` with an unbroadcastable Bitcoin transaction. The user must invoke `withdraw_rbf` to create a replacement transaction, but `sign_btc_transaction` is still open to any caller, so the attacker can immediately repeat the attack on the new RBF pending info. This creates a sustained, repeatable DoS on any individual user's withdrawal: each recovery attempt costs the user gas and NEAR for storage, while the attacker pays only the MPC signing fee per round. Funds are not permanently lost (DAO can call `cancel_withdraw`), but the user is effectively unable to complete a withdrawal without operator intervention.

**Impact class:** Medium — attacker-triggered temporary locking of bridged funds.

---

### Likelihood Explanation

Medium. `btc_pending_sign_id` values are emitted as on-chain events (`Event::GenerateBtcPendingInfo`) and are deterministically derivable from the PSBT inputs. The attacker only needs to observe a new pending ID and call `sign_btc_transaction` before the relayer does. The MPC signing fee is the only economic cost. No privileged access is required.

---

### Recommendation

1. **Restrict callers.** Add `#[trusted_relayer]` or an explicit `require!(env::predecessor_account_id() == btc_pending_info.account_id || is_relayer, ...)` check so only the withdrawal owner or a whitelisted relayer can trigger signing.
2. **Validate `key_version`.** Store the expected `key_version` in `Config` and `require!(key_version == config.expected_key_version, ...)` at the top of `sign_btc_transaction`.
3. **Verify the signature in the callback.** After receiving the MPC response, verify the signature against `public_key` and the `payload` before storing it; panic if verification fails so the slot remains open for a legitimate retry.

---

### Proof of Concept

1. User calls `ft_on_transfer` → bridge creates `BTCPendingInfo` with `btc_pending_id = X`, emits `GenerateBtcPendingInfo`.
2. Attacker observes `X` on-chain.
3. Attacker calls `sign_btc_transaction(X, 0, 999)` attaching the required NEAR deposit.
4. Bridge calls MPC service with `key_version=999`; MPC returns a valid secp256k1 signature but for a key derived under version 999 (different from the bridge's deposit-address key).
5. `sign_btc_transaction_callback` runs: `signatures[0].is_none()` → true; signature stored; `is_all_signed()` → true; `extract_tx_bytes_with_sign()` serializes the PSBT with the wrong-key signature; state advances to `PendingVerify`.
6. Legitimate relayer's subsequent call to `sign_btc_transaction(X, 0, 0)` hits `require!(is_none())` → panics; signing is permanently blocked for this pending info.
7. The serialized transaction is broadcast to Bitcoin and rejected (invalid witness/signature).
8. User calls `withdraw_rbf` → new pending info `Y` created; attacker repeats from step 3 with `Y`.
9. User's withdrawal is indefinitely blocked without DAO/Operator calling `cancel_withdraw`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-26)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L99-103)
```rust
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L145-158)
```rust
            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
            let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L167-195)
```rust
            let mut psbt = btc_pending_info.get_psbt();
            psbt.save_signature(sign_index, signature, public_key);

            btc_pending_info.psbt_hex = psbt.serialize();
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
