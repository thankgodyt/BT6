### Title
NEAR Anti-Spam Deposits Permanently Locked in Contract with No Withdrawal Mechanism — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `request_refund` and `execute_refund` entry points require callers to attach a NEAR deposit as an anti-spam/storage fee. These deposits are explicitly documented as non-refundable and accumulate in the contract's NEAR balance. However, no function exists anywhere in the contract to withdraw this accumulated NEAR. The analog to the BandoRouterV1 bug is exact: fees are collected from callers but permanently locked in the contract with no recovery path.

---

### Finding Description

`request_refund` enforces a minimum attached NEAR deposit:

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
```

The public-facing docstring in `bridge.rs` explicitly states:

> "Requires an attached deposit of at least `required_balance_for_request_refund()`. The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee."

Similarly, `execute_refund` (via `resolve_execute_refund_timelock`) enforces:

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
```

The comment in `refund.rs` sizes the deposit at approximately 2 NEAR per request (to cover up to 200 KB of `tx_bytes` storage). Every successful `request_refund` and `execute_refund` call deposits NEAR into the contract's balance. When a refund request is finalized or rejected, the on-chain storage is freed, but the NEAR that was deposited to cover it is never returned to the caller and never forwarded anywhere.

The only withdrawal function in the contract is `withdraw_protocol_fee` in `management.rs`, which withdraws **nBTC tokens** (NEP-141), not NEAR:

```rust
pub fn withdraw_protocol_fee(&mut self, amount: Option<U128>) -> Promise {
    ...
    self.internal_withdraw_protocol_fee(amount)  // ft_transfer of nBTC
}
```

There is no `withdraw_near`, `withdraw_storage_deposit`, or equivalent function anywhere in the codebase. The accumulated NEAR is permanently locked.

---

### Impact Explanation

Every call to `request_refund` (open to any NEAR account holding a valid BTC deposit proof) and `execute_refund` (open to any NEAR account after the timelock) deposits NEAR that is never recoverable. Over the bridge's lifetime, this accumulates into a growing pool of permanently locked NEAR. The protocol loses access to these funds indefinitely. This matches the allowed impact: **permanent locking of protocol funds**.

---

### Likelihood Explanation

The refund flow is a publicly reachable path — any NEAR account can call `request_refund` with a valid BTC transaction proof. The timelock-gated `execute_refund` is similarly open to any caller. Both are normal operational paths (not edge cases), so NEAR accumulation is guaranteed during ordinary bridge usage.

---

### Recommendation

Add a DAO-gated function to withdraw accumulated NEAR from the contract balance, analogous to `withdraw_protocol_fee` for nBTC:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn withdraw_near(&mut self, amount: Option<NearToken>, receiver_id: AccountId) -> Promise {
    assert_one_yocto();
    let amount = amount.unwrap_or_else(|| env::account_balance());
    Promise::new(receiver_id).transfer(amount)
}
```

Alternatively, refund the storage deposit to the caller when a refund request is finalized or rejected (similar to how NEAR storage deposits work in standard NEP-145 contracts).

---

### Proof of Concept

1. Any NEAR account calls `request_refund` with a valid BTC deposit proof, attaching ≥ `required_balance_for_request_refund()` NEAR (~2 NEAR for a max-size tx).
2. The NEAR is received by the contract. The `request_refund_callback` stores the `RefundRequest` on-chain.
3. After the timelock, any account calls `execute_refund`, attaching ≥ `required_balance_for_execute_refund()` NEAR.
4. The refund is finalized via `verify_refund_finalize_callback`, which removes the `RefundRequest` from storage — freeing the on-chain storage — but the deposited NEAR remains in the contract balance with no path to recovery.
5. Repeat for every refund request. The contract's NEAR balance grows monotonically from these deposits, and no DAO function exists to reclaim it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-535)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L146-153)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L201-205)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L481-494)
```rust
        // Refund confirmed on-chain → drop the request so no further execute_refund
        // is possible. If it was already removed, this is harmlessly a no-op.
        self.data_mut()
            .refund_requests
            .remove(&utxo_storage_keys[0]);

        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);

        true
    }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L19-29)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn withdraw_protocol_fee(&mut self, amount: Option<U128>) -> Promise {
        assert_one_yocto();
        let total_protocol_fee = self.data().cur_available_protocol_fee;
        let amount = amount.map_or(total_protocol_fee, |v| v.0);
        require!(amount > 0 && amount <= total_protocol_fee, "Invalid amount");
        self.data_mut().cur_available_protocol_fee -= amount;
        self.data_mut().acc_claimed_protocol_fee += amount;
        self.internal_withdraw_protocol_fee(amount)
    }
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
