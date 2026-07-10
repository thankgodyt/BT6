### Title
NEAR Storage Deposits from `request_refund` and `execute_refund` Permanently Locked in `satoshi-bridge` Contract — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/api/view.rs`)

---

### Summary
The `satoshi-bridge` contract collects non-refundable NEAR deposits from callers of `request_refund` (2 NEAR each) and `execute_refund` (1 NEAR each), explicitly documented as anti-spam fees. However, no function exists anywhere in the contract to withdraw the accumulated NEAR balance. The `withdraw_protocol_fee` mechanism only transfers nBTC tokens via `ft_transfer` to the nBTC contract — it does not transfer NEAR. As a result, every refund-path call permanently locks NEAR in the contract with no recovery path for the DAO.

---

### Finding Description

`request_refund` and `execute_refund` are public, payable entrypoints that require attached NEAR deposits:

- `required_balance_for_request_refund()` returns **2 NEAR** [1](#0-0) 
- `required_balance_for_execute_refund()` returns **1 NEAR** [2](#0-1) 

Both functions explicitly document that the deposit is **not refunded**:

> "The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee on this permissionless entrypoint." [1](#0-0) 

The `request_refund` entrypoint enforces this minimum deposit: [3](#0-2) 

The `execute_refund` entrypoint enforces its minimum deposit via `resolve_execute_refund_timelock`: [4](#0-3) 

The only fee-withdrawal mechanism in the contract is `withdraw_protocol_fee`, which calls `internal_withdraw_protocol_fee`: [5](#0-4) 

That function exclusively calls `ft_transfer` on the nBTC token contract — it transfers **nBTC tokens**, not NEAR: [6](#0-5) 

There is no `Promise::new(account_id).transfer(amount)` or equivalent NEAR-transfer call anywhere in the contract's management surface. The accumulated NEAR from refund deposits has no withdrawal path.

---

### Impact Explanation

Every call to `request_refund` locks 2 NEAR and every call to `execute_refund` locks 1 NEAR permanently in the contract. The comments acknowledge that the bulk of the deposit (for a normal 1–2 input deposit costing ~0.005 NEAR in storage) is an anti-spam fee — meaning ~1.995 NEAR per `request_refund` call is pure protocol revenue that cannot be claimed. Over time, as the refund system is used, the contract accumulates an ever-growing NEAR balance that is irrecoverable. This is a permanent loss of protocol value with no direct theft of user funds.

**Impact: Medium** — Harmful smart-contract behavior; protocol NEAR funds are permanently locked with no operator intervention path.

---

### Likelihood Explanation

`request_refund` is a public, permissionless entrypoint reachable by any NEAR account. Every legitimate refund request (e.g., a user whose deposit was never finalized) triggers the 2 NEAR lock. `execute_refund` is similarly public. Both are expected to be called in normal bridge operation whenever deposits fail to finalize. The accumulation is certain to occur.

**Likelihood: High** — Certain to happen in any production deployment that processes refunds.

---

### Recommendation

Add a DAO-gated function to withdraw the contract's NEAR balance (or a specified portion of it), analogous to `withdraw_protocol_fee` for nBTC. For example:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn withdraw_near_balance(&mut self, amount: NearToken) -> Promise {
    assert_one_yocto();
    Promise::new(env::predecessor_account_id()).transfer(amount)
}
```

This mirrors the recommendation in the reference report: add a method by which the owner/DAO can withdraw the contract's accumulated native-token balance.

---

### Proof of Concept

1. Any user calls `request_refund(...)` with `attached_deposit = 2 NEAR`. The contract enforces `env::attached_deposit() >= required_balance_for_request_refund()` (2 NEAR). [3](#0-2) 
2. The 2 NEAR is credited to the contract's NEAR account balance. No state variable tracks it; no refund is issued.
3. The DAO calls `withdraw_protocol_fee(None)`. This calls `internal_withdraw_protocol_fee`, which issues `ft_transfer` on the nBTC contract — NEAR balance is untouched. [7](#0-6) 
4. No other function in `management.rs`, `bridge.rs`, or any other module issues a NEAR transfer out of the contract. 
5. The 2 NEAR is permanently locked. Repeat for every `request_refund` and `execute_refund` call.

### Citations

**File:** contracts/satoshi-bridge/src/api/view.rs (L322-328)
```rust
    pub fn required_balance_for_execute_refund(&self) -> NearToken {
        // Measured real storage: ~0.012 NEAR (Bitcoin) up to ~0.134 NEAR (Zcash shielded,
        // whose pending info embeds the Orchard bundle). The deposit is NOT refunded, so
        // 1 NEAR covers the heaviest case and acts as an anti-spam fee on this
        // permissionless entrypoint — refunds are a rare, abnormal event anyway.
        NearToken::from_near(1)
    }
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L330-339)
```rust
    pub fn required_balance_for_request_refund(&self) -> NearToken {
        // request_refund stores a RefundRequest holding the deposit tx_bytes verbatim, so
        // storage grows ~1:1 with tx size (measured: storage ≈ tx_bytes + ~442 bytes). A
        // normal deposit (1-2 inputs, ~500 bytes) costs ~0.005 NEAR, but tx_bytes is capped
        // at MAX_REQUEST_REFUND_TX_BYTES (200 KB) — at that worst case storage is ~2 NEAR.
        // We size the deposit to cover that worst case; for normal deposits the bulk of it
        // is an anti-spam fee on this permissionless entrypoint (the deposit is NOT refunded).
        // Refunds are a rare, abnormal event anyway.
        NearToken::from_near(2)
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
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

**File:** contracts/satoshi-bridge/src/api/management.rs (L21-29)
```rust
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
