### Title
NEAR Deposits from `request_refund` and `execute_refund` Accumulate Permanently With No Withdrawal Mechanism — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

### Summary
The `satoshi-bridge` contract collects non-refundable NEAR deposits from the permissionless `request_refund` (2 NEAR each) and `execute_refund` (1 NEAR each) entrypoints. These deposits accumulate in the contract's account balance indefinitely. No function exists anywhere in the contract to transfer or withdraw accumulated NEAR, so every deposit is permanently locked.

### Finding Description
Both `request_refund` and `execute_refund` are marked `#[payable]` and enforce a minimum attached NEAR deposit before proceeding:

`request_refund` checks:
```rust
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
```
where `required_balance_for_request_refund()` returns `NearToken::from_near(2)`. [1](#0-0) [2](#0-1) 

`execute_refund` (via `resolve_execute_refund_timelock`) checks:
```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
```
where `required_balance_for_execute_refund()` returns `NearToken::from_near(1)`. [3](#0-2) [4](#0-3) 

The code comments explicitly confirm these deposits are never returned:

> "The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee on this permissionless entrypoint" [2](#0-1) 

A grep across all `contracts/satoshi-bridge/src/**/*.rs` for any `Promise::new(...).transfer(...)`, `env::account_balance`, or NEAR-withdrawal pattern returns **no matches**. The only token transfers in the contract are NEP-141 nBTC transfers via `ft_transfer` in `token_transfer.rs`, not native NEAR. [5](#0-4) 

The public API surface (`api/bridge.rs`, `api/management.rs`, `api/view.rs`, `api/chain_signatures.rs`, `api/token_receiver.rs`) contains no function that calls `Promise::new(account).transfer(amount)` for NEAR. There is no DAO-gated or operator-gated NEAR withdrawal function anywhere in the contract.


### Impact Explanation
Every successful `request_refund` call permanently locks 2 NEAR in the contract, and every successful `execute_refund` call permanently locks 1 NEAR. Both entrypoints are permissionless (any NEAR account can call them). Over the operational lifetime of the bridge, these deposits accumulate with no recovery path — not even for the DAO. This constitutes permanent loss of NEAR funds held by the protocol, matching the **Medium** impact class: harmful smart-contract behavior causing stuck funds without direct theft of BTC/nBTC.

### Likelihood Explanation
Medium. The refund flow is a documented, expected operational path (deposits that were never finalized). Every real refund event triggers at least one `request_refund` (2 NEAR lost) and one `execute_refund` (1 NEAR lost). Additionally, the permissionless nature of `request_refund` means any user can trigger the accumulation without any privileged access.

### Recommendation
Add a DAO-gated function to withdraw accumulated NEAR from the contract balance, for example:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn withdraw_near(&mut self, amount: NearToken, recipient: AccountId) -> Promise {
    assert_one_yocto();
    Promise::new(recipient).transfer(amount)
}
```

This mirrors the existing `withdraw_protocol_fee` pattern used for nBTC fees, applied to native NEAR.

### Proof of Concept

1. Alice calls `request_refund` with a valid BTC deposit proof, attaching 2 NEAR.
   - `internal_request_refund` checks `env::attached_deposit() >= 2 NEAR` and proceeds.
   - The 2 NEAR is credited to the bridge contract's account balance.
   - No refund is issued; the comment confirms this is by design.

2. After the timelock, Alice calls `execute_refund`, attaching 1 NEAR.
   - `resolve_execute_refund_timelock` checks `env::attached_deposit() >= 1 NEAR` and proceeds.
   - The 1 NEAR is credited to the bridge contract's account balance.
   - No refund is issued.

3. A search of the entire `contracts/satoshi-bridge/src/` tree finds zero occurrences of `Promise::new(...).transfer(...)` for NEAR. The 3 NEAR from steps 1–2 is permanently locked in the contract with no recovery path for any role, including DAO. [6](#0-5) [7](#0-6)

### Citations

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L11-33)
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

    pub fn internal_transfer_nbtc(&self, account_id: &AccountId, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(account_id.clone(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .transfer_nbtc_callback(account_id.clone(), amount.into()),
            )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
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
