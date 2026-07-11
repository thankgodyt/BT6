### Title
Re-execution of `execute_refund` Permanently Blocked by Single-Key `btc_pending_infos` Mapping — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The bridge explicitly documents that `execute_refund` may be called a second time to re-create a refund transaction (e.g., after a consensus branch change). However, the implementation inserts the refund's `BTCPendingInfo` into a single-key map (`btc_pending_infos`) keyed by a deterministic PSBT hash (`btc_pending_id`). Because the PSBT is built from immutable refund-request data, the hash is identical on every call for the same UTXO. The second call therefore panics with `"pending info already exist"`, and no cleanup path exists while the refund request is still active, leaving the refund permanently stuck until privileged operator intervention.

---

### Finding Description

**Root cause — single-key mapping blocks re-entry**

In `finalize_refund_with_psbt`, after building the refund PSBT, the code inserts a new `BTCPendingInfo` keyed by `btc_pending_id` (the SHA-256 hash of the PSBT payload preimages): [1](#0-0) 

The `require!(.is_none(), "pending info already exist")` guard panics if the key is already present. Because the PSBT is deterministically constructed from the stored `RefundRequest` fields (UTXO outpoint, refund address, amount, gas fee — none of which change between calls), `btc_pending_id` is identical on every invocation for the same UTXO.

**Design intent explicitly contradicts the guard**

The code comment immediately after the insert confirms the intended re-execution semantics: [2](#0-1) 

The request is kept with `executed = true` precisely so `execute_refund` can be called again. The single-key map makes this impossible.

**No cleanup path while the request is active**

`remove_refund_pending_tx_id` (the only way to delete a stale refund pending info) requires the refund request to be absent: [3](#0-2) 

But the request is still present (with `executed = true`), so this call also panics. The two guards create a deadlock:

- `execute_refund` → fails because `btc_pending_id` already in map.
- `remove_refund_pending_tx_id` → fails because refund request still active.

**Entry path is fully public**

`execute_refund` carries no role restriction: [4](#0-3) 

Any NEAR account can trigger the first execution, and any account (or the same user) can attempt the second, hitting the panic.

**`btc_pending_id` generation is deterministic**

The pending ID is a SHA-256 hash of the PSBT payload preimages: [5](#0-4) 

The PSBT is rebuilt from the stored `RefundRequest` (same `tx_bytes`, `vout`, `refund_address`, `gas_fee`) on every call, so the hash is stable across invocations.

---

### Impact Explanation

Once `execute_refund` is called once for a UTXO, the refund enters a stuck state:

1. The `BTCPendingInfo` occupies the `btc_pending_infos` slot.
2. The refund request remains with `executed = true`.
3. A second `execute_refund` (needed if the first BTC tx is dropped or reorganized) panics.
4. `remove_refund_pending_tx_id` also panics.

The user's BTC is locked in the bridge-controlled UTXO with no self-service recovery path. Resolution requires a privileged operator to call `reject_refund` (removing the request) and then `remove_refund_pending_tx_id` (removing the stale pending info) before `execute_refund` can succeed again. This matches **Medium — stuck bridge state requiring operator intervention**.

---

### Likelihood Explanation

The scenario is realistic: a refund BTC transaction may fail to confirm due to fee market conditions, a Bitcoin reorg, or RBF replacement by a miner. The bridge's own comment acknowledges this as an expected operational case. Any user with a pending refund request is exposed after the first `execute_refund` call.

---

### Recommendation

Before inserting the new `BTCPendingInfo`, check whether a pending info for the same `btc_pending_id` already exists and, if so, remove it (or use a different key that incorporates a call counter or timestamp). Alternatively, expose a permissionless cleanup path that allows removal of a stale refund pending info when the associated refund request has `executed == true`, mirroring the double-mapping pattern recommended in the original report.

---

### Proof of Concept

1. Alice deposits BTC; the deposit is never finalized.
2. Alice calls `request_refund` → `refund_requests[utxo_key]` is created.
3. After the timelock, anyone calls `execute_refund(utxo_key, ...)`:
   - `finalize_refund_with_psbt` builds PSBT from stored request data.
   - `btc_pending_id = SHA256(PSBT_preimages)` → inserted into `btc_pending_infos`.
   - `refund_requests[utxo_key].executed = true`.
4. The refund BTC transaction is dropped from the mempool (low fee / reorg).
5. Anyone calls `execute_refund(utxo_key, ...)` again:
   - Same stored request data → same PSBT → same `btc_pending_id`.
   - `btc_pending_infos.insert(...)` returns `Some(...)` → `require!` panics: `"pending info already exist"`.
6. Anyone calls `remove_refund_pending_tx_id(btc_pending_id)`:
   - `refund_requests.contains_key(utxo_key)` is `true` → panics: `"refund request still active"`.
7. Alice's BTC is stuck; only DAO/Operator can break the deadlock via `reject_refund` + `remove_refund_pending_tx_id`.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L366-372)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L395-401)
```rust
        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L418-424)
```rust
        require!(
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L416-425)
```rust
pub fn generate_btc_pending_sign_id(payload_preimages: &[Vec<u8>]) -> String {
    let hash_bytes = env::sha256_array(
        payload_preimages
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<u8>>(),
    );
    hex::encode(hash_bytes)
}
```
