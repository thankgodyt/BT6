### Title
Missing Re-execution Path for Stuck Refund Transactions After MPC Signing Leaves User Funds Permanently Locked - (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

When a refund transaction is MPC-signed and transitions to `PendingVerify` stage but the resulting Bitcoin transaction gets stuck in the mempool (e.g., due to insufficient fee), there is no mechanism to re-execute the refund or bump the fee. The code comments and the `executed` flag explicitly indicate the design intent to allow re-execution of `execute_refund`, but the implementation blocks it when an existing `BTCPendingInfo` with the same deterministic ID is still present. This creates a permanently stuck state with no recovery path, locking the user's deposit UTXO in the bridge's MPC key.

---

### Finding Description

**Vulnerability class**: Stuck/frozen state due to missing retry/resend mechanism for a critical signed transaction — the direct analog of the external report's "missing resend for dropped messages" pattern.

**Root cause — `finalize_refund_with_psbt` blocks re-execution:** [1](#0-0) 

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
```

The `btc_pending_id` is a deterministic SHA-256 hash of the PSBT payload preimages: [2](#0-1) 

Since a refund PSBT is built from fixed inputs (the deposit UTXO, the fixed refund address, and the gas fee stored in the `RefundRequest`), the same `btc_pending_id` is always produced for the same refund request. Calling `execute_refund` a second time will always collide with the existing entry and panic.

**The design intent contradicts the implementation.** The code comment and the `executed` flag explicitly promise re-execution is possible: [3](#0-2) 

And `load_refund_request_for_execute` explicitly permits re-entry when `executed == true`: [4](#0-3) 

**The deadlock — no escape hatch exists:**

Once the `BTCPendingInfo` is in `PendingVerify` (signing succeeded, tx broadcast but stuck):

1. **`execute_refund` again** → panics at `finalize_refund_with_psbt` with "pending info already exist".
2. **`remove_refund_pending_tx_id`** → blocked because the refund request is still active: [5](#0-4) 

3. **No RBF mechanism for refunds** — unlike withdrawals, which have `withdraw_rbf` and `cancel_withdraw`: [6](#0-5) 

Refunds have no equivalent fee-bumping path.

4. **DAO `reject_refund` does not help** — it removes the refund request, allowing `remove_refund_pending_tx_id` to run, but the UTXO remains in `verified_deposit_utxo` permanently (nothing ever removes from this set), so `request_refund` for the same UTXO will always fail with "UTXO already verified via deposit": [7](#0-6) 

The deposit UTXO is permanently unrecoverable through any standard bridge flow.

---

### Impact Explanation

A user's deposit UTXO becomes permanently locked in the bridge's MPC-controlled key. The user cannot recover their BTC through the refund flow, and no operator intervention mechanism exists to unblock the specific case where a signed refund `BTCPendingInfo` is in `PendingVerify` while its refund request is still active. This matches the allowed impact: **stuck bridge state requiring operator intervention** (with no such intervention path available), and potentially **permanent locking of user funds**.

---

### Likelihood Explanation

Bitcoin mempool congestion is a routine occurrence. Refund gas fees are fixed at `request_refund` time and stored immutably in the `RefundRequest`: [8](#0-7) 

If mempool fees spike between the time the refund is requested and the time the signed transaction is broadcast, the transaction will be stuck and eventually evicted from the mempool (~2 weeks). Any user whose refund transaction experiences this common network condition will be permanently locked out of their funds.

---

### Recommendation

1. **Add a privileged cleanup function** (DAO/Operator) that removes a stale refund `BTCPendingInfo` in `PendingVerify` stage even when the refund request is still active, breaking the deadlock.
2. **Or**, in `finalize_refund_with_psbt`, detect and remove an existing `BTCPendingInfo` with the same ID before inserting the new one, making re-execution truly idempotent as the design intends.
3. **Or**, implement a fee-bumping (RBF) mechanism for refund transactions analogous to `withdraw_rbf` for withdrawals.

---

### Proof of Concept

1. User deposits BTC; the deposit is not processed (e.g., wrong metadata).
2. User calls `request_refund` → `RefundRequest` stored with `executed = false`.
3. After timelock, user calls `execute_refund` → `finalize_refund_with_psbt` creates `BTCPendingInfo` in `PendingSign`, inserts UTXO into `verified_deposit_utxo`, sets `executed = true`.
4. `sign_btc_transaction` is called → MPC signing succeeds → `sign_btc_transaction_callback` stores all signatures, calls `to_pending_verify_stage()`, moves `BTCPendingInfo` to `PendingVerify`.
5. The signed transaction is broadcast but mempool fees spike; the transaction is stuck and eventually evicted.
6. User calls `execute_refund` again → `load_refund_request_for_execute` passes (because `executed == true`) → `finalize_refund_with_psbt` panics: **"pending info already exist"**.
7. User calls `remove_refund_pending_tx_id` → panics: **"refund request still active"**.
8. DAO calls `reject_refund` → refund request removed; UTXO remains in `verified_deposit_utxo`.
9. User calls `request_refund` for the same UTXO → `request_refund_callback` panics: **"UTXO already verified via deposit"**.
10. **User's BTC is permanently locked with no recovery path.**

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L253-258)
```rust
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
```rust
        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-299)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }

    /// If the user's Withdraw is not verified within a certain time, the protocol can actively cancel the Withdraw through RBF, with the gas fee borne by the user.
    ///
    /// # Arguments
    ///
    /// * `original_btc_pending_verify_id` - Pending verify ID of the original transaction.
    /// * `output` - Modified output.
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```
