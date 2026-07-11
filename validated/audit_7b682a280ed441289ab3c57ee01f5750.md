### Title
Unvalidated Zero `last_block_height` from BTC Light Client Causes Wrong Zcash `branch_id` and Stuck Withdrawals/Refunds - (`File: contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs`)

---

### Summary

The Zcash bridge fetches the current block height from the BTC light client contract via `get_last_block_height_promise()` and uses the returned `last_block_height` to derive the Zcash consensus `branch_id` and `expiry_height` for every Zcash transaction (withdrawals, refunds, RBF replacements, active UTXO management). Nowhere in any callback is the returned value checked to be non-zero. If the light client returns `0`, the bridge silently constructs a Zcash transaction with the wrong consensus branch and an already-expired height, producing a transaction that the Zcash network will reject. The user's nZEC is consumed by the bridge but the corresponding Zcash transaction can never confirm, leaving funds stuck in a pending state that requires operator intervention.

---

### Finding Description

The bridge calls `get_last_block_height_promise()` in five distinct Zcash-specific flows:

1. **Withdrawal initiation** – `ft_on_transfer_withdraw_chain_specific` → `ft_on_transfer_callback`
2. **Refund execution** – `internal_execute_refund` → `execute_refund_callback`
3. **Withdrawal RBF** – `withdraw_rbf_chain_specific` → `withdraw_rbf_callback`
4. **Withdrawal cancel** – `cancel_withdraw_chain_specific` → `cancel_withdraw_callback`
5. **Active UTXO management** – `active_utxo_management_chain_specific` → `active_utxo_management_callback`

In every callback the raw `u32` value is used directly without a zero-check:

```rust
// contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs
pub fn ft_on_transfer_callback(
    ...
    #[callback_unwrap] last_block_height: u32,   // ← never checked for 0
) -> U128 {
    let expiry_height = self.get_expiry_height(&chain_specific_data, last_block_height);
    let psbt = PsbtWrapper::new(input, output, orchard_bundle,
                                expiry_height, last_block_height, ...);
    ...
}
```

`PsbtWrapper::new` immediately calls `get_branch_id(current_height, config)`:

```rust
// contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs
fn get_branch_id(current_height: u32, config: &Config) -> BranchId {
    config.chain.get_branch_id(current_height)
}
```

And `get_branch_id` falls through to the default `BranchId::Nu6` when `block_height` is below the NU6.1 activation threshold:

```rust
// contracts/satoshi-bridge/src/network.rs
pub fn get_branch_id(&self, block_height: u32) -> BranchId {
    if block_height >= block_height_update.nu6_2_update { return BranchId::Nu6_2; }
    if block_height >= block_height_update.nu6_1_update { return BranchId::Nu6_1; }
    BranchId::Nu6   // ← returned when block_height == 0
}
```

Mainnet NU6.1 activates at block 3,146,400 and NU6.2 at 3,364,600. A `last_block_height` of `0` causes the bridge to sign every Zcash transaction with `BranchId::Nu6`, which is invalid on the live network.

Simultaneously, `get_expiry_height` computes the valid range as `[0 + gap, 0 + 2*gap]` (e.g., `[1000, 2000]` with the default `expiry_height_gap = 1000`). Any transaction built with this expiry height is already expired on a chain at block 3,000,000+.

The BTC light client interface declares the return type as `u32` with no sentinel for "not yet synced":

```rust
// contracts/satoshi-bridge/src/btc_light_client/mod.rs
#[ext_contract(ext_btc_light_client)]
pub trait BtcLightClient {
    fn get_last_block_height(&self) -> u32;
}
```

A `u32` default-initialised to `0` (e.g., an unsynced or freshly deployed light client) is a valid return value that the bridge accepts without complaint.

---

### Impact Explanation

When `last_block_height == 0` is returned:

- The Zcash transaction is constructed with `BranchId::Nu6` and `expiry_height ≤ 2000`.
- The MPC network signs this transaction (it has no knowledge of the Zcash chain state).
- The signed transaction is broadcast but immediately rejected by every Zcash node: wrong consensus branch and already-expired height.
- The user's nZEC tokens are consumed by the bridge (`ft_on_transfer_callback` returns `U128(0)`, signalling full consumption) but the corresponding ZEC never arrives.
- The withdrawal is stuck in `PendingSign` / `PendingVerify` state. Cancel and RBF paths also call `get_last_block_height_promise`, so they produce equally invalid transactions if the light client still returns `0`.
- Operator intervention is required to unblock the stuck state.

This matches the **Medium** allowed impact: *stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

The BTC light client is an external contract. Scenarios where it returns `0` include:

- A freshly deployed or unsynced light client (the Rust `Default` for `u32` is `0`).
- A light client upgrade that resets state before re-syncing.
- A bug in the light client that causes it to return `0` for a period.

Any bridge user who initiates a Zcash withdrawal, refund execution, or RBF during such a window will have their transaction silently broken. The user has no way to detect this before submitting.

---

### Recommendation

Add an explicit non-zero guard in every Zcash callback that receives `last_block_height` before using it:

```rust
// In ft_on_transfer_callback, execute_refund_callback, and all RBF callbacks:
#[callback_unwrap] last_block_height: u32,
{
    require!(last_block_height > 0, "Invalid block height: light client returned 0");
    // ... rest of the logic
}
```

This mirrors the pattern already used for deposit amounts:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs
require!(deposit_amount > 0, "Invalid deposit_amount");
```

A minimum sensible threshold (e.g., the NU6 activation height) could be used instead of `> 0` for stronger protection.

---

### Proof of Concept

1. Deploy the bridge with a Zcash light client that returns `last_block_height = 0` (e.g., an unsynced instance).
2. Alice holds nZEC and calls `ft_transfer_call` to initiate a Zcash withdrawal.
3. `ft_on_transfer_withdraw_chain_specific` fires `get_last_block_height_promise`.
4. The light client returns `0`.
5. `ft_on_transfer_callback` receives `last_block_height = 0`.
6. `get_branch_id(0, config)` returns `BranchId::Nu6`.
7. `get_expiry_height(None, 0)` computes `expiry_height = 1000`.
8. `PsbtWrapper::new(...)` stores `branch_id = Nu6`, `expiry_height = 1000`.
9. The MPC signs the transaction.
10. The transaction is broadcast; every Zcash node rejects it (wrong branch, expired).
11. Alice's nZEC is consumed; her ZEC never arrives; the withdrawal is permanently stuck. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L119-134)
```rust
        #[callback_unwrap] last_block_height: u32,
    ) -> U128 {
        let expiry_height = self.get_expiry_height(&chain_specific_data, last_block_height);
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        let psbt = PsbtWrapper::new(
            input,
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(target_btc_address.clone()),
            self.internal_config(),
        );

        self.create_btc_pending_info(sender_id, amount.0, target_btc_address, psbt, max_gas_fee);
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L77-93)
```rust
        let orchard = orchard_policy::extract_orchard_bundle(
            orchard_bundle_bytes,
            proof_size_enforcement(get_branch_id(current_height, config)),
        )
        .unwrap_or_else(|_| {
            env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: failed to extract Orchard bundle")
        });

        Self {
            branch_id: get_branch_id(current_height, config),
            expiry_height,
            vout,
            vin,
            inputs_utxo: inputs,
            orchard,
            recipient_address,
        }
```

**File:** contracts/satoshi-bridge/src/network.rs (L53-65)
```rust
    pub fn get_branch_id(&self, block_height: u32) -> BranchId {
        let block_height_update = BranchIdUpdateBlockHeight::new(self);
        if block_height_update.nu6_2_update != 0 && block_height >= block_height_update.nu6_2_update
        {
            return BranchId::Nu6_2;
        }
        if block_height_update.nu6_1_update != 0 && block_height >= block_height_update.nu6_1_update
        {
            return BranchId::Nu6_1;
        }

        BranchId::Nu6
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/mod.rs (L160-165)
```rust
#[ext_contract(ext_btc_light_client)]
pub trait BtcLightClient {
    fn verify_transaction_inclusion(&self, #[serializer(borsh)] args: ProofArgs) -> bool;
    fn verify_transaction_inclusion_v2(&self, #[serializer(borsh)] args: ProofArgsV2) -> bool;
    fn get_last_block_height(&self) -> u32;
}
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L86-115)
```rust
        #[callback_unwrap] last_block_height: u32,
    ) {
        // Enforce the timelock and that the UTXO has not been finalized via deposit.
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);

        let expiry_height = REFUND_EXPIRY_HEIGHT;
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        // Shielded refund routes funds through the Orchard bundle (no transparent
        // output); transparent refund pays a single t-address output.
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };

        let mut psbt = PsbtWrapper::new(
            vec![outpoint],
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(refund_request.refund_address.clone()),
            self.internal_config(),
        );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L134-135)
```rust
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        require!(deposit_amount > 0, "Invalid deposit_amount");
```
