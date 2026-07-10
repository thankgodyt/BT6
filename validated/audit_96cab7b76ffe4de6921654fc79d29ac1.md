### Title
Unprotected `sign_btc_transaction` Allows Any Caller to Trigger MPC Signing with Attacker-Controlled `key_version`, Potentially Corrupting Pending Withdrawals - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

### Summary
The `sign_btc_transaction` function in the satoshi-bridge contract has no access control. Any unprivileged NEAR account can call it for any pending withdrawal, supplying an attacker-controlled `key_version`. This causes the MPC to sign the transaction payload with a key derived from the wrong version, producing a signature that does not correspond to the UTXO-controlling key. If that invalid signature is committed to state and the transaction is assembled, the resulting Bitcoin transaction is cryptographically invalid and will be rejected by the Bitcoin network, leaving the withdrawal stuck.

### Finding Description
`sign_btc_transaction` in `contracts/satoshi-bridge/src/api/chain_signatures.rs` carries only `#[payable]` and `#[pause(except(roles(Role::DAO)))]`. It has no `#[trusted_relayer]`, no `#[access_control_any]`, and no manual caller check:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,          // ← fully attacker-controlled
) -> PromiseOrValue<bool> {
``` [1](#0-0) 

Compare this to privileged operations such as `cancel_withdraw` and `active_utxo_management`, which both carry `#[access_control_any(roles(Role::DAO, Role::Operator))]`, and deposit functions such as `verify_deposit_v2`, which carry `#[trusted_relayer]`: [2](#0-1) [3](#0-2) 

Inside `internal_sign_btc_transaction`, the `path` is correctly derived from the UTXO's stored path, but `key_version` is passed through verbatim from the caller into the MPC `SignRequest`:

```rust
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← attacker-supplied
})
``` [4](#0-3) 

`sign_promise` forwards the full attached deposit to the MPC contract and issues the signing call: [5](#0-4) 

In NEAR Chain Signatures, the derived key is a function of both `path` **and** `key_version`. Using a wrong `key_version` produces a signature from a completely different key than the one that controls the UTXO. The callback then saves this signature alongside the correct public key (derived from the UTXO path, not from `key_version`):

```rust
let public_key = self.generate_btc_public_key(&...vutxos[sign_index].get_path()).inner;
...
btc_pending_info.signatures[sign_index] = Some(signature.clone());
...
psbt.save_signature(sign_index, signature, public_key);
``` [6](#0-5) 

Once `signatures[sign_index]` is set to `Some`, the check `require!(btc_pending_info.signatures[sign_index].is_none(), "Already signed")` prevents any legitimate re-signing of that slot. If this is the last input, `extract_tx_bytes_with_sign()` is called and the `SignedBtcTransaction` event is emitted, signalling relayers to broadcast the (invalid) transaction. [7](#0-6) 

The `btc_pending_sign_id` needed to target a specific withdrawal is publicly observable via the `GenerateBtcPendingInfo` event emitted during withdrawal creation: [8](#0-7) 

### Impact Explanation
**Scenario A — PSBT finalization validates the signature**: `extract_tx_bytes_with_sign()` panics, rolling back `signatures[sign_index]`. The slot is freed, but the attacker can repeat the call indefinitely, continuously blocking the legitimate relayer from signing and permanently delaying the withdrawal (DoS requiring operator intervention via `cancel_withdraw`).

**Scenario B — PSBT finalization does not validate the signature**: The invalid signature is committed to state, the `SignedBtcTransaction` event is emitted with invalid transaction bytes, the relayer broadcasts a transaction that Bitcoin rejects, and the withdrawal is permanently stuck in `PendingVerify` state. Recovery requires a privileged `cancel_withdraw` call by DAO/Operator.

In both scenarios the user's nBTC is locked inside the bridge until operator intervention, matching **Medium — attacker-triggered temporary locking of bridged funds**.

### Likelihood Explanation
- The `btc_pending_sign_id` is emitted as a public on-chain event, so any observer can obtain it.
- The attacker only needs to attach enough NEAR to cover the MPC signing deposit (a small, known amount).
- No special role, leaked key, or privileged access is required.
- The attack can be automated to front-run every legitimate `sign_btc_transaction` call.

### Recommendation
Add `#[access_control_any(roles(Role::DAO, Role::UnrestrictedRelayer))]` (or `#[trusted_relayer]`) to `sign_btc_transaction`, consistent with how deposit verification functions are protected. Additionally, validate `key_version` against a contract-configured expected value before forwarding it to the MPC, so even a privileged caller cannot accidentally or maliciously use the wrong key version.

### Proof of Concept
1. User initiates a withdrawal: calls `ft_transfer_call` on the nBTC contract with a `Withdraw` message. The bridge emits `GenerateBtcPendingInfo { btc_pending_id: "abc123", ... }`.
2. Attacker observes the event and immediately calls:
   ```
   sign_btc_transaction(
       btc_pending_sign_id = "abc123",
       sign_index = 0,
       key_version = 999,   // wrong version
   )
   ```
   with sufficient attached NEAR deposit.
3. The MPC signs the PSBT hash using the key derived from `(path, key_version=999)` — a key that does not control the UTXO.
4. `sign_btc_transaction_callback` saves `signatures[0] = Some(<wrong-key signature>)` and calls `psbt.save_signature(0, wrong_sig, correct_pubkey)`.
5. If this is the only input, `extract_tx_bytes_with_sign()` is called. The assembled transaction carries a signature that does not satisfy the UTXO's locking script.
6. The `SignedBtcTransaction` event is emitted; the relayer broadcasts the transaction; Bitcoin rejects it.
7. The withdrawal remains in `PendingVerify` state indefinitely. The legitimate relayer cannot re-sign (slot already occupied). Operator must call `cancel_withdraw` to recover.

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-27)
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
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-73)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-285)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L62-68)
```rust
    pub fn sign_promise(&self, request: SignRequest) -> Promise {
        let config = self.internal_config();
        ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
            .with_static_gas(GAS_FOR_SIGN_CALL)
            .with_attached_deposit(env::attached_deposit())
            .sign(request)
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L99-103)
```rust
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L144-170)
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
            btc_pending_info.last_sign_time_sec = nano_to_sec(env::block_timestamp());
            Event::BtcInputSignature {
                account_id: &account_id,
                btc_pending_id: &btc_pending_sign_id,
                sign_index,
                signature: &signature,
            }
            .emit();
            let mut psbt = btc_pending_info.get_psbt();
            psbt.save_signature(sign_index, signature, public_key);

            btc_pending_info.psbt_hex = psbt.serialize();
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L171-196)
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L134-140)
```rust
        Event::UtxoRemoved { utxo_storage_keys }.emit();
        Event::GenerateBtcPendingInfo {
            account_id: &sender_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
    }
```
