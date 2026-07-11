### Title
`check_withdraw_chain_specific` on Zcash Performs No Validation, Allowing RBF Without Gas Fee Increase - (File: `contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs`)

### Summary
The Zcash implementation of `check_withdraw_chain_specific` is a completely empty stub. The Bitcoin implementation of the same function enforces that an RBF (Replace-By-Fee) transaction must pay a strictly higher gas fee than the transaction it replaces. Because the Zcash version skips this check entirely, any user can submit a `withdraw_rbf` call on Zcash with an equal or lower gas fee, creating a new pending transaction that will not actually replace the original on the Zcash network.

### Finding Description
In `contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs`, `check_withdraw_chain_specific` enforces the core RBF invariant: [1](#0-0) 

```rust
pub(crate) fn check_withdraw_chain_specific(
    original_tx_btc_pending_info: &BTCPendingInfo,
    gas_fee: u128,
) {
    let max_gas_fee = original_tx_btc_pending_info.get_max_gas_fee();
    let additional_gas_amount = gas_fee.saturating_sub(max_gas_fee);
    require!(additional_gas_amount > 0, "No gas increase.");
}
```

The Zcash counterpart in `contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs` is a no-op — all parameters are prefixed with `_` and the body is empty: [2](#0-1) 

```rust
pub(crate) fn check_withdraw_chain_specific(
    _original_tx_btc_pending_info: &BTCPendingInfo,
    _gas_fee: u128,
) {
}
```

The `define_rbf_callback!` macro wires this function into the `withdraw_rbf_callback`, `cancel_withdraw_callback`, and related RBF paths on Zcash: [3](#0-2) 

The public entry point `withdraw_rbf` in `contracts/satoshi-bridge/src/api/bridge.rs` is callable by any user who has an active pending withdrawal: [4](#0-3) 

### Impact Explanation
Without the gas-increase check, a Zcash user can call `withdraw_rbf` with the same or a lower gas fee than the original transaction. The bridge will:
1. Accept the call and create a new `BTCPendingInfo` entry for the replacement transaction.
2. Request an MPC signature for a transaction that the Zcash network will not accept as a replacement (fee not increased).
3. Leave the bridge with two live pending entries for the same withdrawal UTXO — the original and the invalid RBF — neither of which can be finalized without operator intervention.

This matches the **Medium** impact class: attacker-triggered stuck bridge state requiring operator intervention, and bypass of the bridge's RBF fee-increase policy.

### Likelihood Explanation
Any NEAR account that has initiated a Zcash withdrawal can call `withdraw_rbf` immediately. No special role, leaked key, or external dependency is required. The call path is fully public and reachable.

### Recommendation
Apply the same gas-increase guard in the Zcash `check_withdraw_chain_specific` that exists in the Bitcoin version:

```rust
pub(crate) fn check_withdraw_chain_specific(
    original_tx_btc_pending_info: &BTCPendingInfo,
    gas_fee: u128,
) {
    let max_gas_fee = original_tx_btc_pending_info.get_max_gas_fee();
    let additional_gas_amount = gas_fee.saturating_sub(max_gas_fee);
    require!(additional_gas_amount > 0, "No gas increase.");
}
```

### Proof of Concept
1. User initiates a Zcash withdrawal via `ft_transfer_call`, creating a pending withdrawal with `gas_fee = X`.
2. User calls `withdraw_rbf(original_btc_pending_verify_id, output, chain_specific_data)` with a new `output` whose total fee equals or is less than `X`.
3. `check_withdraw_chain_specific` is invoked but does nothing — no `require!` fires.
4. The bridge creates a second `BTCPendingInfo` for the replacement transaction and requests an MPC signature.
5. The Zcash network rejects the replacement (fee not increased); the original may or may not confirm.
6. Both pending entries remain in bridge state; the withdrawal is stuck until an operator manually intervenes via `cancel_withdraw` or `clear_invalid_pending_verify_rbf`.

### Citations

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L56-64)
```rust
    pub(crate) fn check_withdraw_chain_specific(
        original_tx_btc_pending_info: &BTCPendingInfo,
        gas_fee: u128,
    ) {
        // Ensure that the RBF transaction pays more gas than the previous transaction.
        let max_gas_fee = original_tx_btc_pending_info.get_max_gas_fee();
        let additional_gas_amount = gas_fee.saturating_sub(max_gas_fee);
        require!(additional_gas_amount > 0, "No gas increase.");
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L85-104)
```rust
define_rbf_callback!(
    withdraw_rbf_chain_specific,
    withdraw_rbf_callback,
    internal_withdraw_rbf
);
define_rbf_callback!(
    cancel_withdraw_chain_specific,
    cancel_withdraw_callback,
    internal_cancel_withdraw
);
define_rbf_callback!(
    active_utxo_management_rbf_chain_specific,
    active_utxo_management_rbf_callback,
    internal_active_utxo_management_rbf
);
define_rbf_callback!(
    cancel_active_utxo_management_chain_specific,
    cancel_active_utxo_management_callback,
    internal_cancel_active_utxo_management
);
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L214-218)
```rust
    pub(crate) fn check_withdraw_chain_specific(
        _original_tx_btc_pending_info: &BTCPendingInfo,
        _gas_fee: u128,
    ) {
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
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
```
