### Title
Missing Authorization Check on `sign_btc_transaction` Allows Any Account to Trigger MPC Signing with Attacker-Controlled `key_version` — (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary
`sign_btc_transaction` carries no access-control guard and no ownership check, so any unprivileged NEAR account can invoke MPC signing for any pending withdrawal with an attacker-supplied `key_version`. This is the direct analog of the reported pattern: a sensitive protocol operation that should be restricted to an authorized caller is reachable by anyone.

---

### Finding Description

Every proof-submission entry point in the bridge (`verify_deposit_v2`, `verify_withdraw_v2`, `verify_refund_finalize`, etc.) is decorated with `#[trusted_relayer]`, which restricts callers to whitelisted relayers or bypass-role holders. [1](#0-0) 

`sign_btc_transaction`, however, carries only `#[payable]` and `#[pause]`: [2](#0-1) 

There is no check that `env::predecessor_account_id()` equals `btc_pending_info.account_id`, and no relayer whitelist check. The function delegates to `internal_sign_btc_transaction`, which builds a `SignRequest` with the **fully attacker-controlled** `key_version` field and submits it to the MPC chain-signatures service: [3](#0-2) 

The `path` and `payload` are derived from the PSBT (not attacker-controlled), but `key_version` selects which MPC key is used to produce the signature. If the MPC service accepts a non-zero `key_version`, the returned signature corresponds to a different public key than the one committed in the PSBT inputs.

The callback stores whatever signature the MPC returns without validating it against the PSBT's expected public key: [4](#0-3) 

Once stored, the slot is permanently locked by the "Already signed" guard: [5](#0-4) 

The legitimate relayer's subsequent call for the same `sign_index` is rejected. If all input slots are filled with signatures from the wrong key, `is_all_signed()` triggers finalization, the invalid signed transaction bytes are emitted, and the BTC transaction is broadcast — but rejected by the Bitcoin network because the signatures do not satisfy the PSBT's committed public keys.

---

### Impact Explanation

The user's nBTC is already transferred out of their account (via `ft_transfer_call` → `ft_on_transfer`) and is locked inside the bridge's pending-withdrawal accounting. With an unspendable BTC transaction on-chain, the user cannot receive their BTC. The bridge state is stuck in `PendingVerify` with a transaction that can never confirm, requiring DAO/Operator intervention via `cancel_withdraw` (RBF) to unblock the user. This matches the allowed medium impact: **"stuck bridge state requiring operator intervention"** and **"attacker-triggered temporary locking of bridged funds."**

---

### Likelihood Explanation

Medium. The attack requires no privileged access — any NEAR account can call `sign_btc_transaction`. The attacker must front-run the legitimate relayer (observable via mempool/indexer) and use a `key_version` that the MPC service accepts but maps to a different signing key. Whether the deployed MPC service accepts non-zero `key_version` values is not determinable from the contract code alone, but the missing guard is the root cause regardless.

---

### Recommendation

Apply `#[trusted_relayer]` to `sign_btc_transaction` (consistent with all other sensitive bridge operations), or add an explicit ownership check:

```rust
require!(
    env::predecessor_account_id() == btc_pending_info.account_id
        || self.is_trusted_relayer(&env::predecessor_account_id()),
    "Unauthorized: caller is not the transaction owner or a trusted relayer"
);
```

Additionally, validate that the signature returned by the MPC service is consistent with the public key committed in the PSBT before storing it.

---

### Proof of Concept

1. User calls `ft_transfer_call` on the nBTC contract → `ft_on_transfer` → `create_btc_pending_info` creates a `BTCPendingInfo` in `PendingSign` state for `btc_pending_id = "abc123"`.
2. Attacker observes the new pending entry on-chain.
3. Attacker calls `sign_btc_transaction("abc123", 0, 999)` with `key_version = 999` (attacker-chosen).
4. `internal_sign_btc_transaction` submits `SignRequest { payload, path, key_version: 999 }` to the MPC service.
5. If the MPC service returns a signature (for key version 999), `sign_btc_transaction_callback` stores it in `btc_pending_info.signatures[0]`.
6. Legitimate relayer calls `sign_btc_transaction("abc123", 0, 0)` → panics with `"Already signed"`.
7. With all slots filled by wrong-key signatures, `is_all_signed()` triggers finalization; the invalid signed transaction is emitted and broadcast.
8. Bitcoin network rejects the transaction (signatures do not match the PSBT's committed public keys).
9. User's nBTC remains locked in `PendingVerify` state; DAO/Operator must issue a `cancel_withdraw` RBF to recover funds. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-72)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
```

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L76-113)
```rust
    pub fn internal_sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> Promise {
        let pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);

        let public_keys: Vec<_> = pending_info
            .vutxos
            .iter()
            .map(|vutxo| self.generate_btc_public_key(&vutxo.get_path()))
            .collect();

        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
        let payload = btc_pending_info
            .get_psbt()
            .get_hash_to_sign(sign_index, &public_keys);
        let path = btc_pending_info.vutxos[sign_index].get_path();
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
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L154-159)
```rust
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
            btc_pending_info.last_sign_time_sec = nano_to_sec(env::block_timestamp());
```
