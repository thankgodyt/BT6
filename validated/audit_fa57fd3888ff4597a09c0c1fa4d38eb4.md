### Title
Missing RBF Expiry-Height Lower-Bound Guard Against Original Transaction — (`contracts/satoshi-bridge/src/zcash_utils/types.rs`, `zcash_utils/contract_methods.rs`)

---

### Summary

`get_expiry_height` validates the user-supplied `expiry_height` only against the current chain window `[last_block_height + gap, last_block_height + 2*gap]`. It never compares the new value against the original transaction's `expiry_height`, which is stored in the serialized PSBT and is fully recoverable. An unprivileged user can therefore submit a `withdraw_rbf` call whose RBF transaction expires on-chain **before** the original, leaving both entries stuck in `PendingVerify` inside `btc_pending_infos` until operator intervention.

---

### Finding Description

**Entry point** — `withdraw_rbf` (public, no role gate): [1](#0-0) 

The call flows through `withdraw_rbf_chain_specific` → `get_last_block_height_promise` → `withdraw_rbf_callback`: [2](#0-1) 

Inside the callback, `get_expiry_height` is called with the user-controlled `chain_specific_data`: [3](#0-2) 

The only guard is:

```
expiry_height >= last_block_height + gap
    && expiry_height <= last_block_height + 2 * gap
```

There is **no check** that `expiry_height >= original_psbt.expiry_height`. The original PSBT's `expiry_height` is stored in `BTCPendingInfo.psbt_hex` and is fully recoverable via `get_psbt()` → `PsbtWrapper::deserialize()`: [4](#0-3) [5](#0-4) 

The validated `expiry_height` is then passed directly into `generate_psbt_from_original_psbt_and_new_output` and forwarded verbatim to `PsbtWrapper::from_original_psbt`, which sets it without any comparison to the original: [6](#0-5) [7](#0-6) 

**Concrete scenario**:

| Event | Block height |
|---|---|
| Original tx created, user picks max `expiry_height = H1 + 2*gap` | H1 |
| User calls `withdraw_rbf` with `expiry_height = H2 + gap` | H2 (H1 < H2 < H1 + gap) |
| RBF `expiry_height` = H2 + gap < H1 + 2*gap = original `expiry_height` | — |

The RBF transaction expires on-chain before the original. Because Zcash mempool semantics replace the original with the RBF, neither transaction confirms. Both entries remain in `btc_pending_infos` as `PendingVerify` (`WithdrawOriginal` and `WithdrawUserRbf`).

---

### Impact Explanation

The user's nZEC is locked. The bridge holds both the original and the RBF entry in `PendingVerify` indefinitely. Recovery requires the operator to wait for `max_btc_tx_pending_sec` to elapse and then call `cancel_withdraw` to issue a cancel-RBF: [8](#0-7) 

Until that operator action completes, the user's withdrawal is stuck. No funds are stolen; the impact is a stuck withdrawal requiring operator intervention — matching the **Low** scoped impact.

---

### Likelihood Explanation

The path is reachable by any unprivileged user who has a pending withdrawal in `PendingVerify`. The only precondition is that the original transaction was created with `expiry_height > last_block_height_at_rbf_time + gap` (i.e., the user originally chose a higher expiry, or enough blocks elapsed between creation and the RBF call). This is a normal operational scenario. The attacker only harms their own withdrawal.

---

### Recommendation

In `get_expiry_height` (or in `withdraw_rbf_callback` before calling `generate_psbt_from_original_psbt_and_new_output`), deserialize the original PSBT and enforce:

```rust
let original_psbt = original_tx_btc_pending_info.get_psbt();
require!(
    expiry_height >= original_psbt.expiry_height,
    "RBF expiry_height must be >= original transaction expiry_height"
);
```

Since `PsbtWrapper::deserialize` is already called inside `generate_psbt_from_original_psbt_and_new_output` → `get_psbt()`, the original `expiry_height` is available at zero extra cost.

---

### Proof of Concept

State-level test (no chain required):

1. Create a withdrawal with `expiry_height = H1 + 2*gap` at block H1.
2. Advance mock block height to H2 where `H1 < H2 < H1 + gap`.
3. Call `withdraw_rbf` with `ChainSpecificData { expiry_height: H2 + gap, ... }`.
4. Assert the RBF `BTCPendingInfo` is created successfully (no panic — the current guard passes).
5. Assert `rbf_psbt.expiry_height (= H2 + gap) < original_psbt.expiry_height (= H1 + 2*gap)` — the invariant is violated.
6. Simulate both transactions expiring without confirmation; assert both entries remain in `btc_pending_infos` as `PendingVerify`, with no user-accessible recovery path until `max_btc_tx_pending_sec` elapses.

### Citations

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

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L40-62)
```rust
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
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L167-190)
```rust
    pub(crate) fn get_expiry_height(
        &self,
        chain_specific_data: &Option<ChainSpecificData>,
        last_block_height: u32,
    ) -> u32 {
        let expiry_height = if let Some(chain_specific_data) = chain_specific_data {
            chain_specific_data.expiry_height
        } else {
            last_block_height + self.get_config().expiry_height_gap
        };

        require!(
            expiry_height >= last_block_height + self.get_config().expiry_height_gap
                && expiry_height <= last_block_height + 2 * self.get_config().expiry_height_gap,
            format!(
                "Invalid expiry height: {}. Expected value between {} and {}.",
                expiry_height,
                last_block_height + self.get_config().expiry_height_gap,
                last_block_height + 2 * self.get_config().expiry_height_gap
            )
        );

        expiry_height
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L261-278)
```rust
    pub(crate) fn generate_psbt_from_original_psbt_and_new_output(
        &self,
        original_tx_btc_pending_info: &BTCPendingInfo,
        output: Vec<TxOut>,
        orchard_bundle_bytes: Option<Vec<u8>>,
        expiry_height: u32,
        current_height: u32,
    ) -> PsbtWrapper {
        let original_psbt = original_tx_btc_pending_info.get_psbt();
        PsbtWrapper::from_original_psbt(
            original_psbt,
            output,
            orchard_bundle_bytes,
            expiry_height,
            current_height,
            self.internal_config(),
        )
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L24-32)
```rust
pub struct PsbtWrapper {
    branch_id: BranchId,
    expiry_height: u32,
    vin: Vec<ZcashTxIn<Authorized>>,
    vout: Vec<ZcashTxOut>,
    inputs_utxo: Vec<ZcashTxOut>,
    orchard: Option<ParsedOrchardBundle>,
    recipient_address: Option<String>,
}
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L140-148)
```rust
        Self {
            branch_id: get_branch_id(current_height, config),
            expiry_height,
            vin: original_psbt.vin,
            vout,
            inputs_utxo: original_psbt.inputs_utxo,
            orchard,
            recipient_address: original_psbt.recipient_address,
        }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L299-301)
```rust
        let expiry_height = read_u32_le(&mut rdr)
            .unwrap_or_else(|_| env::panic_str("ERR_INVALID_PSBT: failed to read expiry_height"));

```

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L29-37)
```rust
        let original_tx_btc_pending_info =
            self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
        require!(
            nano_to_sec(env::block_timestamp()) - original_tx_btc_pending_info.create_time_sec
                > self.internal_config().max_btc_tx_pending_sec,
            "Please wait user rbf"
        );
        original_tx_btc_pending_info.assert_not_canceled();
        original_tx_btc_pending_info.assert_withdraw_original_pending_verify_tx();
```
