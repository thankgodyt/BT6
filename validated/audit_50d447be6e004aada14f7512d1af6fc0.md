### Title
Missing RBF Gas-Fee Increase Enforcement in Zcash Withdrawal Path - (File: `contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs`)

---

### Summary

The bridge maintains two parallel implementations of `check_withdraw_chain_specific` — one for Bitcoin and one for Zcash. The Bitcoin implementation enforces that any Replace-By-Fee (RBF) transaction must pay a strictly higher gas fee than the original. The Zcash implementation is a complete no-op, silently omitting this enforcement. This is a direct structural analog to the reported vault.teal.tmpl mismatch: a security check present in one version of the logic is absent in the parallel version.

---

### Finding Description

The bridge uses a feature-flag pattern to compile either the Bitcoin or Zcash code path. Both paths expose a `check_withdraw_chain_specific` function that is called during RBF and cancel-withdraw operations to validate the new gas fee.

**Bitcoin implementation** (`bitcoin_utils/contract_methods.rs`, lines 56–64) enforces a strict fee bump:

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

**Zcash implementation** (`zcash_utils/contract_methods.rs`, lines 214–218) is a complete no-op:

```rust
pub(crate) fn check_withdraw_chain_specific(
    _original_tx_btc_pending_info: &BTCPendingInfo,
    _gas_fee: u128,
) {
}
```

This function is invoked in both `rbf/withdraw.rs` and `rbf/cancel_withdraw.rs` for the active chain's RBF path. On Zcash, the call resolves to the empty body, meaning no fee-increase validation is performed. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

Without the fee-increase check, an unprivileged user initiating a Zcash withdrawal RBF can supply any `gas_fee` value — including one equal to or lower than the original transaction's `max_gas_fee`. The Zcash RBF callbacks (`withdraw_rbf_callback`, `cancel_withdraw_callback`) build a new `PsbtWrapper` and call `internal_withdraw_rbf` / `internal_cancel_withdraw` with the caller-supplied `gas_fee` without any floor enforcement. [3](#0-2) 

Concretely:

1. **Policy bypass**: A user can submit repeated RBF transactions with an unchanged or decreasing gas fee, violating the bridge's intended fee-bump policy and potentially causing the Zcash transaction to remain unconfirmed indefinitely.
2. **Stuck bridge state requiring operator intervention**: Because the bridge tracks pending infos and the UTXO is locked while a pending transaction exists, a stuck RBF chain can permanently lock the user's bridged ZEC until an operator manually intervenes — matching the "Medium. Bypass of bridge limits or policies, or attacker-triggered temporary locking of bridged funds" impact class.

---

### Likelihood Explanation

The entry point is the public `withdraw_rbf_chain_specific` function, reachable by any NEAR account that holds a pending Zcash withdrawal. No privileged role is required. The attacker only needs to call the RBF method with a `gas_fee` equal to or below the original, which the Zcash path accepts without complaint. [4](#0-3) 

---

### Recommendation

Apply the same fee-bump enforcement to the Zcash `check_withdraw_chain_specific` that exists in the Bitcoin version:

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

Additionally, consider consolidating the shared logic into a single function in `rbf/mod.rs` or `refund.rs` so that both chains cannot diverge silently in the future — directly addressing the root cause identified in the external report. [1](#0-0) 

---

### Proof of Concept

1. User burns nZEC and initiates a Zcash withdrawal, creating a `BTCPendingInfo` with `max_gas_fee = F`.
2. The Zcash transaction is broadcast but remains unconfirmed.
3. User calls `withdraw_rbf_chain_specific` (Zcash feature) with `gas_fee = F` (same as original, or even `gas_fee = 1`).
4. `check_withdraw_chain_specific` is called — it is a no-op, so no `require!` fires.
5. `internal_withdraw_rbf` creates a new `BTCPendingInfo` with the same (or lower) fee, producing a transaction that miners will not prefer over the original.
6. The UTXO remains locked in the bridge's pending state. The user repeats step 3 indefinitely, keeping the funds stuck without operator intervention. [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L16-35)
```rust
            pub(crate) fn $method(
                &mut self,
                user_account_id: AccountId,
                original_btc_pending_verify_id: String,
                output: Vec<TxOut>,
                chain_specific_data: Option<ChainSpecificData>,
            ) {
                let predecessor_account_id = env::predecessor_account_id();
                let _ = self.get_last_block_height_promise().then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(GAS_RBF_CALL_BACK)
                        .$callback_name(
                            user_account_id,
                            original_btc_pending_verify_id,
                            output,
                            chain_specific_data,
                            predecessor_account_id,
                        ),
                );
            }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L38-82)
```rust
        #[near]
        impl Contract {
            #[private]
            pub fn $callback_name(
                &mut self,
                account_id: AccountId,
                original_btc_pending_verify_id: String,
                output: Vec<TxOut>,
                chain_specific_data: Option<ChainSpecificData>,
                presecessor_account_id: AccountId,
                #[callback_unwrap] last_block_height: u32,
            ) {
                let expiry_height = self.get_expiry_height(&chain_specific_data, last_block_height);
                let orchard_bundle_bytes = chain_specific_data.map(|c| c.orchard_bundle_bytes);

                let original_tx_btc_pending_info =
                    self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);

                let new_psbt = self.generate_psbt_from_original_psbt_and_new_output(
                    original_tx_btc_pending_info,
                    output,
                    orchard_bundle_bytes.map(|b| b.0),
                    expiry_height,
                    last_block_height,
                );

                let btc_pending_id = self.$internal_fn(
                    &account_id,
                    original_btc_pending_verify_id,
                    new_psbt,
                    presecessor_account_id,
                );

                self.internal_unwrap_mut_account(&account_id)
                    .btc_pending_sign_ids
                    .insert(btc_pending_id.clone());

                Event::GenerateBtcPendingInfo {
                    account_id: &account_id,
                    btc_pending_id: &btc_pending_id,
                }
                .emit();
            }
        }
    };
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
