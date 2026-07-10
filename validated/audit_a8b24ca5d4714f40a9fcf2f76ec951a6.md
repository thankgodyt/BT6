### Title
Refund Execution Creates Irrecoverable Stuck State When Refund Transaction Fails to Confirm — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

The `execute_refund` flow marks the deposit UTXO as verified and creates a `BTCPendingInfo` entry in a single atomic step. If the resulting Bitcoin refund transaction fails to confirm (e.g., due to insufficient gas fee or network fee spike), there is no RBF mechanism for refunds, and re-calling `execute_refund` is blocked by the existing `BTCPendingInfo`. The only operator escape hatch (`reject_refund` + `remove_refund_pending_tx_id`) leaves the UTXO permanently in `verified_deposit_utxo`, blocking all future recovery paths for the user's BTC.

### Finding Description

**Step 1 — `execute_refund` marks the UTXO verified and creates a `BTCPendingInfo`.**

In `finalize_refund_with_psbt` (called from `internal_execute_refund`):

```rust
// Mark UTXO as verified to prevent verify_deposit later
self.data_mut()
    .verified_deposit_utxo
    .insert(utxo_storage_key.clone());
``` [1](#0-0) 

And immediately after:

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
``` [2](#0-1) 

The `btc_pending_id` is derived deterministically from the PSBT signing payloads via `generate_btc_pending_sign_id`, which is a pure SHA-256 hash of the payload bytes. [3](#0-2) 

For a refund, the PSBT is built from a fixed set of inputs (the deposit UTXO, the refund address, and the refund amount = `deposit_amount - gas_fee`). All three are frozen at `request_refund` time. Therefore, re-calling `execute_refund` for the same request produces an identical PSBT and the same `btc_pending_id`, causing the `require!` to panic with `"pending info already exist"`.

**Step 2 — No RBF mechanism exists for refund transactions.**

The `PendingInfoState` enum defines RBF variants only for withdrawals and active UTXO management:

```rust
pub enum PendingInfoState {
    WithdrawOriginal(OriginalState),
    WithdrawUserRbf(RbfState),
    WithdrawCancelRbf(RbfState),
    ActiveUtxoManagementOriginal(OriginalState),
    ActiveUtxoManagementRbf(RbfState),
    ActiveUtxoManagementCancelRbf(RbfState),
    Refund(OriginalState),   // ← no RefundRbf, no RefundCancelRbf
}
``` [4](#0-3) 

The public API exposes `withdraw_rbf`, `cancel_withdraw`, `active_utxo_management_rbf`, and `cancel_active_utxo_management`, but no equivalent for refunds. [5](#0-4) 

**Step 3 — `remove_refund_pending_tx_id` is blocked while the refund request is active.**

```rust
require!(
    !self
        .data()
        .refund_requests
        .contains_key(&utxo_storage_keys[0]),
    "refund request still active"
);
``` [6](#0-5) 

The refund request is kept with `executed = true` until `verify_refund_finalize` succeeds (which requires the transaction to confirm on-chain). So while the refund transaction is unconfirmed, neither re-execution nor cleanup is possible.

**Step 4 — Operator escape hatch leaves BTC permanently locked.**

The only operator path is:
1. `reject_refund` → removes the refund request from storage. [7](#0-6) 
2. `remove_refund_pending_tx_id` → now succeeds (refund request gone), removes the `BTCPendingInfo`.

But `verified_deposit_utxo` still contains the UTXO key. `request_refund_callback` checks:

```rust
require!(
    !self
        .data()
        .verified_deposit_utxo
        .contains(&utxo_storage_key),
    "UTXO already verified via deposit"
);
``` [8](#0-7) 

This permanently blocks any new `request_refund` for the same UTXO. `verify_deposit` is similarly blocked by the same set. There is no public function to remove entries from `verified_deposit_utxo`. The user's BTC is permanently locked in the bridge's MPC-controlled deposit address with no on-chain recovery path.

### Impact Explanation

A user's deposited BTC can be permanently locked in the bridge's MPC-controlled deposit address with no on-chain recovery mechanism. After the stuck state is reached:
- `verify_deposit` is blocked (UTXO in `verified_deposit_utxo`)
- `request_refund` is blocked (same check)
- `execute_refund` is blocked (same `btc_pending_id` already exists)
- `remove_refund_pending_tx_id` is blocked (refund request still active)

Even after DAO intervention (`reject_refund` + `remove_refund_pending_tx_id`), the UTXO remains in `verified_deposit_utxo` with no removal path, making the lock permanent at the contract level. This constitutes permanent locking of user funds.

### Likelihood Explanation

The trigger condition is a refund transaction that fails to confirm on Bitcoin. This is realistic when:
- `config.max_btc_gas_fee` is set conservatively and Bitcoin mempool fees spike after the refund is created
- The gas fee stored in the `RefundRequest` at creation time becomes insufficient for current network conditions
- Network congestion causes the transaction to be evicted from mempools

The `gas_fee` is fixed at `request_refund` time (either from `config.max_btc_gas_fee` or a custom value). [9](#0-8) 

Bitcoin fee markets are volatile; a fee that was adequate at request time can become inadequate by execution time, especially given the `refund_timelock_sec` (default 2 days) and `unsafe_refund_timelock_sec` (default 14 days) delays before execution. [10](#0-9) 

### Recommendation

1. **Add an RBF mechanism for refunds**: Introduce `RefundRbf` and `RefundCancelRbf` states in `PendingInfoState` and corresponding `refund_rbf` / `cancel_refund` API functions, mirroring the withdrawal RBF pattern.

2. **Decouple UTXO verification from refund execution**: Do not insert into `verified_deposit_utxo` until the refund transaction is confirmed via `verify_refund_finalize_callback`. This allows re-execution with a higher fee if the first attempt fails.

3. **Allow `remove_refund_pending_tx_id` while the request is active**: Permit DAO/Operator to remove a stale `BTCPendingInfo` for an executed refund request without requiring the request to be rejected first, so that `execute_refund` can be re-called with updated parameters.

4. **Add a DAO function to remove entries from `verified_deposit_utxo`**: As a safety valve for stuck states, allow the DAO to clear a UTXO from the verified set so that recovery paths remain open.

### Proof of Concept

1. User deposits BTC to their bridge deposit address.
2. User calls `request_refund` with a valid proof. `RefundRequest` is stored with `gas_fee = config.max_btc_gas_fee` (e.g., 5000 sat).
3. After `refund_timelock_sec` passes, anyone calls `execute_refund`. `finalize_refund_with_psbt` runs:
   - `verified_deposit_utxo.insert(utxo_storage_key)` — UTXO marked verified.
   - `btc_pending_infos.insert(btc_pending_id, ...)` — `BTCPendingInfo` created.
   - `refund_request.executed = true` — request kept.
4. Bitcoin mempool fees spike to 50 sat/vbyte. The refund transaction (built with 5000 sat fee) is too low-priority and is never confirmed.
5. Anyone calls `execute_refund` again → panics: `"pending info already exist"` (same PSBT → same `btc_pending_id`).
6. Anyone calls `remove_refund_pending_tx_id` → panics: `"refund request still active"`.
7. DAO calls `reject_refund` → refund request removed.
8. DAO calls `remove_refund_pending_tx_id` → `BTCPendingInfo` removed.
9. User calls `request_refund` again → panics: `"UTXO already verified via deposit"`.
10. User's BTC is permanently locked in the bridge's MPC deposit address.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
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

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
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

**File:** contracts/satoshi-bridge/src/refund.rs (L535-541)
```rust
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-553)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L69-77)
```rust
pub enum PendingInfoState {
    WithdrawOriginal(OriginalState),
    WithdrawUserRbf(RbfState),
    WithdrawCancelRbf(RbfState),
    ActiveUtxoManagementOriginal(OriginalState),
    ActiveUtxoManagementRbf(RbfState),
    ActiveUtxoManagementCancelRbf(RbfState),
    Refund(OriginalState),
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-428)
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

    /// Verify that the active UTXO management has been successful, and burn the gas fee.
    ///
    /// # Deprecated
    /// Use `verify_active_utxo_management_v2` instead, which includes coinbase proof for stronger verification.
    ///
    /// # Arguments
    ///
    /// * `tx_id` - The transaction ID of the successfully on-chain UTXO management.
    /// * `tx_block_blockhash` - The block hash where the transaction is located.
    /// * `tx_index` - The index of the transaction in the block.
    /// * `merkle_proof` - Merkle proof of the transaction.
    ///
    /// # Returns
    ///
    /// bool - Whether nBTC burning was successful.
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    #[deprecated(note = "use verify_active_utxo_management_v2")]
    pub fn verify_active_utxo_management(
        &mut self,
        tx_id: String,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
    ) -> Promise {
        self.internal_verify_active_utxo_management_entry(
            tx_id,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            None,
        )
    }

    /// Verify that the active UTXO management has been successful, and burn the gas fee.
    /// Includes coinbase proof for stronger transaction inclusion verification.
    ///
    /// # Arguments
    ///
    /// * `tx_id` - The transaction ID of the successfully on-chain UTXO management.
    /// * `proof` - Transaction inclusion proof with coinbase verification.
    ///
    /// # Returns
    ///
    /// bool - Whether nBTC burning was successful.
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_active_utxo_management_v2(
        &mut self,
        tx_id: String,
        proof: TxInclusionProof,
    ) -> Promise {
        self.internal_verify_active_utxo_management_entry(
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
        )
    }

    /// The number of UTXOs in a Withdraw transaction is managed through outputs that are all change addresses.
    ///
    /// # Arguments
    ///
    /// * `input` - Used to generate the PSBT input.
    /// * `output` -Used to generate the PSBT output.
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn active_utxo_management(&mut self, input: Vec<OutPoint>, output: Vec<TxOut>) {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        self.active_utxo_management_chain_specific(account_id, input, output);
    }

    /// The initiator of active UTXO management accelerates the transaction by increasing the gas fee.
    ///
    /// # Arguments
    ///
    /// * `original_btc_pending_verify_id` - Pending verify ID of the original transaction.
    /// * `output` - Modified output.
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn active_utxo_management_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
    ) {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);
        self.active_utxo_management_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }

    /// Active UTXO management transactions that have not been verified for a long time are allowed to be canceled through RBF.
    ///
    /// # Arguments
    ///
    /// * `original_btc_pending_verify_id` - Pending verify ID of the original transaction.
    /// * `output` - Modified output.
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_active_utxo_management(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
    ) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
        self.cancel_active_utxo_management_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
