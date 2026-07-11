### Title
Orphaned In-Flight MPC Callback Panics After Early-Exit Cleanup Deletes RBF `BTCPendingInfo` — (`contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

A concrete interleaving of NEAR asynchronous transactions allows the early-exit cleanup branch of `sign_btc_transaction` to delete an RBF `BTCPendingInfo` entry while an MPC sign callback (`sign_btc_transaction_callback`) for that same entry is still in-flight. When the callback lands it calls `internal_unwrap_btc_pending_info` / `internal_unwrap_mut_btc_pending_info` on the now-deleted key and panics with `"BTC pending info not exist"`, permanently discarding the MPC signature and leaving the RBF transaction in an unrecoverable deleted-but-signed limbo.

---

### Finding Description

**Relevant code paths:**

`sign_btc_transaction` (early-exit branch): [1](#0-0) 

`internal_sign_btc_transaction` (dispatches MPC promise + schedules callback): [2](#0-1) 

`sign_btc_transaction_callback` (panicking site): [3](#0-2) 

`internal_unwrap_mut_btc_pending_info` (panics on missing key): [4](#0-3) 

**The race sequence (all steps are separate NEAR transactions; state is not locked between them):**

| Step | Transaction | Effect |
|------|-------------|--------|
| T1 | `sign_btc_transaction(rbf_id, ...)` | Passes `assert_pending_sign()`, `original_tx_id` exists → falls through to `internal_sign_btc_transaction`, dispatches MPC sign promise, schedules `sign_btc_transaction_callback`. RBF entry still in `btc_pending_infos` with `stage=PendingSign`. |
| T2 | `verify_withdraw(original_id, ...)` → burn callback | Original tx verified; burn callback removes original from `btc_pending_infos` (line 143 of `nbtc/burn.rs`). RBF entry is **not** removed — it is left orphaned. |
| T3 | `sign_btc_transaction(rbf_id, ...)` (second call) | `assert_pending_sign()` still passes (stage unchanged). `check_btc_pending_info_exists(original_tx_id)` returns `false`. Early-exit fires: removes RBF id from `btc_pending_sign_ids`, calls `internal_remove_btc_pending_info(rbf_id)`. Returns `Value(true)`. |
| T4 | MPC callback from T1 lands | `internal_unwrap_btc_pending_info(rbf_id)` → `.expect("BTC pending info not exist")` → **panic**. | [5](#0-4) 

**Why T2 is valid:** `internal_verify_withdraw_entry` only blocks verification of an *RBF* tx if its original is gone; it has no guard preventing the *original* tx from being verified while an RBF tx is in `PendingSign`. [6](#0-5) 

**Why T3 is valid:** There is no "sign in-flight" flag. After T1 dispatches the MPC promise, the RBF entry's `stage` remains `PendingSign` and `btc_pending_sign_ids` still contains the id (removal only happens inside the callback when `is_all_signed()`). So the second call passes every guard and reaches the early-exit deletion. [7](#0-6) 

**Why `sign_btc_transaction` is publicly reachable:** The function carries only `#[pause(except(roles(Role::DAO)))]` — no `trusted_relayer` or ACL check. Any account can call it when the contract is unpaused. [8](#0-7) 

---

### Impact Explanation

The callback panic (T4) causes the NEAR receipt to fail. The MPC signature computed for the RBF transaction is permanently discarded. The RBF `BTCPendingInfo` was already deleted in T3, so there is no way to re-sign or recover it. The RBF transaction is stuck in a signed-but-unrecorded limbo: the MPC key material was consumed, the PSBT was never finalized on-chain, and the entry no longer exists to be cleaned up. This is a publicly reachable stuck-state / panic-driven fault in the production bridge signing path, matching the **Low** allowed impact tier.

No direct fund theft occurs because the original transaction was already verified before T3.

---

### Likelihood Explanation

The window between T1 (MPC sign dispatch) and T4 (callback landing) spans multiple NEAR blocks (MPC signing latency). During that window, T2 (original tx verification) and T3 (second `sign_btc_transaction` call) can both execute. T3 requires only knowledge of `rbf_id`, which is emitted as a public `GenerateBtcPendingInfo` event. Any observer can trigger T3 without any privileged role. The scenario is therefore reachable by an unprivileged actor who monitors on-chain events.

---

### Recommendation

Add an "in-flight sign" guard. Before dispatching the MPC promise in `internal_sign_btc_transaction`, set a per-input flag (e.g., a `signing_in_flight: bool` field or a dedicated `PendingInfoStage::Signing` variant). In `sign_btc_transaction`, reject (or skip the early-exit) if any input is already in-flight. Clear the flag in `sign_btc_transaction_callback` regardless of success or failure. This prevents the early-exit cleanup from racing with an outstanding callback.

Alternatively, in the early-exit branch, check whether any in-flight sign promises exist before deleting the entry, or defer deletion to the callback itself.

---

### Proof of Concept

```
1. Original tx (orig_id) is in PendingVerify; RBF tx (rbf_id) is in PendingSign.
2. Call sign_btc_transaction(rbf_id, 0, 0)
   → internal_sign_btc_transaction dispatches MPC sign promise P1
   → sign_btc_transaction_callback(account, rbf_id, 0) is scheduled as P1's callback
3. Call verify_withdraw(orig_id, ...) → burn callback removes orig_id from btc_pending_infos
4. Call sign_btc_transaction(rbf_id, 0, 0) again
   → assert_pending_sign() passes (stage still PendingSign)
   → check_btc_pending_info_exists(orig_id) == false
   → early-exit: btc_pending_sign_ids.remove(rbf_id), internal_remove_btc_pending_info(rbf_id)
   → returns Value(true)
5. P1 callback fires:
   → internal_unwrap_btc_pending_info(rbf_id) → expect("BTC pending info not exist") → PANIC
```

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

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L27-43)
```rust
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L134-153)
```rust
    #[private]
    pub fn sign_btc_transaction_callback(
        &mut self,
        account_id: AccountId,
        btc_pending_sign_id: String,
        sign_index: usize,
    ) -> bool {
        if let Ok(result_bytes) = env::promise_result_checked(0, MAX_SIGNATURE_RESULT) {
            let signature = serde_json::from_slice::<SignatureResponse>(&result_bytes)
                .expect("Invalid signature");

            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
            let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L197-202)
```rust
                let is_original_tx = btc_pending_info.get_original_tx_id().is_none();
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L384-393)
```rust
    pub fn internal_unwrap_mut_btc_pending_info(
        &mut self,
        btc_pending_id: &String,
    ) -> &mut BTCPendingInfo {
        self.data_mut()
            .btc_pending_infos
            .get_mut(btc_pending_id)
            .map(Into::into)
            .expect("BTC pending info not exist")
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L44-52)
```rust
    ) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        btc_pending_info.assert_withdraw_related_pending_verify_tx();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            require!(
                self.check_btc_pending_info_exists(original_tx_id),
                "original tx already verified"
            );
        }
```
