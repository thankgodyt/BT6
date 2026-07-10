### Title
Permanently Locked NEAR Storage Deposits in Refund Flow — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
The `satoshi-bridge` contract collects NEAR-denominated storage deposits from unprivileged callers in `internal_request_refund` and `resolve_execute_refund_timelock`. When refund requests are finalized and their on-chain storage is freed, the deposited NEAR accumulates in the contract's balance with no mechanism to return it to depositors or for any privileged role to withdraw it.

### Finding Description
Two public-facing refund entry points enforce a minimum attached NEAR deposit before proceeding:

**`internal_request_refund`** (called by any account submitting a refund): [1](#0-0) 

**`resolve_execute_refund_timelock`** (called by any account executing a refund): [2](#0-1) 

These deposits are transferred into the contract's NEAR balance. The corresponding cleanup path — `verify_refund_finalize_callback` — removes the `RefundRequest` from `refund_requests` and the `BTCPendingInfo` from `btc_pending_infos`, freeing the on-chain storage: [3](#0-2) 

However, neither `verify_refund_finalize_callback` nor any other function in the contract returns the storage deposits to the original depositors or provides a privileged withdrawal path for accumulated NEAR. The `ContractData` struct tracks protocol fee accounting fields (`cur_available_protocol_fee`, `acc_claimed_protocol_fee`, etc.) and a `lost_found` map for nBTC, but contains no equivalent tracking or withdrawal mechanism for NEAR storage deposits: [4](#0-3) 

The `internal_withdraw_protocol_fee` function in `token_transfer.rs` only handles nBTC (NEP-141) fee withdrawal, not NEAR: [5](#0-4) 

### Impact Explanation
Every unprivileged user who submits a refund request (`request_refund`) or executes one (`execute_refund`) must attach NEAR. After the refund lifecycle completes and storage is freed, those NEAR deposits remain permanently locked in the contract. Over time, across all refund operations, this constitutes a growing pool of permanently irrecoverable user funds. This matches the allowed Medium impact: *permanent locking of user funds without direct theft*.

### Likelihood Explanation
Likelihood is high. Refunds are a core bridge recovery path — any deposit that fails to mint nBTC (e.g., wrong amount, wrong address, expired) triggers the refund flow. Every such user is required to attach NEAR and loses it permanently upon finalization. No special conditions or attacker sophistication are required; the loss occurs through normal, intended usage.

### Recommendation
1. Track each depositor's storage deposit amount at the time of `request_refund` and `execute_refund`.
2. Return the corresponding deposit to the original caller when `verify_refund_finalize_callback` removes the associated storage entries.
3. Alternatively, add a privileged `withdraw_near` function (restricted to `Role::DAO`) that can sweep accumulated NEAR deposits, analogous to `internal_withdraw_protocol_fee` for nBTC fees.

### Proof of Concept
1. Alice calls `request_refund(...)` attaching `required_balance_for_request_refund()` NEAR → NEAR is transferred to the contract.
2. Alice (or anyone) calls `execute_refund(...)` attaching `required_balance_for_execute_refund()` NEAR → more NEAR transferred to the contract.
3. A relayer calls `verify_refund_finalize(...)` → `verify_refund_finalize_callback` removes `refund_requests[key]` and `btc_pending_infos[tx_id]`, freeing storage.
4. Alice's NEAR deposits remain in the contract balance. No function exists to return them. They are permanently locked.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L202-205)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L483-491)
```rust
        self.data_mut()
            .refund_requests
            .remove(&utxo_storage_keys[0]);

        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);
```

**File:** contracts/satoshi-bridge/src/lib.rs (L141-146)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
    pub refund_requests: IterableMap<String, VRefundRequest>,
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L11-21)
```rust
    pub fn internal_withdraw_protocol_fee(&self, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .withdraw_protocol_fee_callback(amount.into()),
            )
    }
```
