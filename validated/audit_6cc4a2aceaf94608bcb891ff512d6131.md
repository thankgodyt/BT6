### Title
Arithmetic Underflow in `verify_active_utxo_management_burn_callback` Permanently Blocks Cancel-RBF Finalization - (File: contracts/satoshi-bridge/src/nbtc/burn.rs)

### Summary

In `verify_active_utxo_management_burn_callback`, the line `reserved_protocol_fee - btc_pending_info.burn_amount` performs a plain Rust subtraction. For a cancel-active-UTXO-management RBF transaction, the cancel RBF's `burn_amount` is always strictly greater than the original transaction's `max_gas_fee` (which is what `reserved_protocol_fee` reads). With `overflow-checks = true` in the build profile, this subtraction panics on every such callback, permanently preventing the cancel-RBF from being finalized. Because the nBTC burn cross-contract call completes before the callback runs, the burn is irreversible while all bridge-state updates are rolled back, leaving the contract in an inconsistent stuck state.

### Finding Description

**Root cause — mismatched invariant between cancel-RBF creation and its finalization callback.**

**Step 1 — Cancel-RBF creation (`cancel_active_utxo_management.rs`).**

When `internal_cancel_active_utxo_management` is called, the code enforces that the new gas fee is strictly larger than the original transaction's `max_gas_fee`:

```
let additional_gas_amount = gas_fee.saturating_sub(max_gas_fee);
require!(additional_gas_amount > 0, "No gas increase.");
```

The cancel-RBF pending info is then initialised with `burn_amount = gas_fee` (the new, higher fee). Crucially, `do_cancel` is called on the original transaction — but `update_max_gas_fee` is **not** called, so the original transaction's `max_gas_fee` remains at its old, lower value. [1](#0-0) 

**Step 2 — Finalization callback (`burn.rs`).**

`verify_active_utxo_management_burn_callback` is called after the nBTC burn succeeds. For any RBF transaction (`get_original_tx_id()` returns `Some`), it reads the original transaction's `max_gas_fee` as `reserved_protocol_fee` and then subtracts the RBF's `burn_amount`:

```rust
let reserved_protocol_fee = original_tx_btc_pending_info.get_max_gas_fee(); // old, lower value
let unused_reserved_protocol_fee =
    reserved_protocol_fee - btc_pending_info.burn_amount;  // burn_amount > reserved → PANIC
```

Because `burn_amount = cancel_rbf_gas_fee > original_max_gas_fee = reserved_protocol_fee`, the subtraction underflows. With `overflow-checks = true` (confirmed in `CLAUDE.md`), this is a guaranteed panic on every cancel-active-UTXO-management RBF verification attempt. [2](#0-1) 

**Contrast with the regular active-UTXO-management RBF path (`active_utxo_management.rs`).**

The non-cancel RBF path calls `update_max_gas_fee(gas_fee)` on the original transaction, so `reserved_protocol_fee == burn_amount` and the subtraction yields zero safely. The cancel path omits this update, creating the discrepancy. [3](#0-2) 

**Overflow-checks confirmation.** [4](#0-3) 

### Impact Explanation

**Severity: Medium — stuck bridge state requiring operator intervention.**

1. The nBTC burn cross-contract call completes and is committed in its own NEAR receipt before the callback executes. The burn is irreversible.
2. The callback panics; all state mutations inside it are rolled back. The cancel-RBF `BTCPendingInfo` entry remains in `btc_pending_infos`, the original transaction remains marked as canceled, and `cur_reserved_protocol_fee` retains the reserved amount that can never be released through the normal path.
3. Every subsequent attempt to call the verification function for this cancel-RBF will re-enter the same callback and panic again — the stuck state is permanent without a privileged migration or contract upgrade.
4. Protocol fees (nBTC) are permanently locked in `cur_reserved_protocol_fee` and cannot be reclaimed via `cur_available_protocol_fee`.

This matches the allowed impact: *"Medium. Harmful smart-contract behavior without direct funds theft, including … stuck bridge state requiring operator intervention."*

### Likelihood Explanation

The cancel-active-UTXO-management RBF is a routine operational action taken whenever a UTXO-consolidation transaction is stuck on-chain and needs fee bumping. The code itself **requires** `additional_gas_amount > 0`, meaning every single cancel-RBF invocation sets `burn_amount > max_gas_fee`. There is no code path that avoids the underflow once a cancel-RBF is created. The bug is therefore triggered deterministically on every cancel-active-UTXO-management RBF finalization attempt.

### Recommendation

In `verify_active_utxo_management_burn_callback`, replace the bare subtraction with a guarded form that accounts for the cancel-RBF case where `burn_amount` may exceed the original `max_gas_fee`. The simplest fix mirrors the STETHVault resolution: compute `unused_reserved_protocol_fee` only when `reserved_protocol_fee >= burn_amount`, and treat any excess as zero (the additional gas was already deducted from `cur_available_protocol_fee` at cancel-RBF creation time):

```rust
let unused_reserved_protocol_fee =
    reserved_protocol_fee.saturating_sub(btc_pending_info.burn_amount);
```

Alternatively, call `update_max_gas_fee(gas_fee)` on the original transaction inside `internal_cancel_active_utxo_management`, mirroring the regular RBF path, so that `reserved_protocol_fee` always equals `burn_amount` at callback time.

Apply the same fix to the analogous subtraction in the `else` branch (line 211) for defensive correctness. [5](#0-4) 

### Proof of Concept

1. Operator initiates an active-UTXO-management transaction; suppose `max_gas_fee = 1000` satoshis.
2. The transaction stalls on-chain. Operator calls `cancel_active_utxo_management` with a new PSBT whose gas fee is `1500` satoshis.
   - `additional_gas_amount = 1500 - 1000 = 500 > 0` ✓ (passes the require)
   - `cur_available_protocol_fee -= 500`; `cur_reserved_protocol_fee += 500`
   - Cancel-RBF `BTCPendingInfo` created with `burn_amount = 1500`
   - Original tx's `max_gas_fee` remains `1000` (not updated)
3. Cancel-RBF is signed by MPC, broadcast to Bitcoin, and confirmed.
4. Relayer calls the verification entry-point for the cancel-RBF.
5. `verify_active_utxo_management_burn_promise` fires: nBTC burn of `1500` succeeds and is committed.
6. `verify_active_utxo_management_burn_callback` executes:
   - `reserved_protocol_fee = original_tx.get_max_gas_fee() = 1000`
   - `unused_reserved_protocol_fee = 1000 - 1500` → **integer underflow → panic**
7. Callback state is rolled back. The cancel-RBF entry persists in `btc_pending_infos`. `cur_reserved_protocol_fee` is not decremented. The 1500-satoshi nBTC burn is permanent. Every retry panics identically.

### Citations

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L50-64)
```rust
        btc_pending_info.gas_fee = gas_fee;
        btc_pending_info.burn_amount = gas_fee;
        btc_pending_info.actual_received_amount = actual_received_amount;
        // Ensure that the RBF transaction pays more gas than the previous transaction.
        let max_gas_fee = original_tx_btc_pending_info.get_max_gas_fee();
        let additional_gas_amount = gas_fee.saturating_sub(max_gas_fee);
        require!(additional_gas_amount > 0, "No gas increase.");
        require!(
            self.data().cur_available_protocol_fee >= additional_gas_amount,
            "Insufficient protocol fee"
        );
        self.data_mut().cur_available_protocol_fee -= additional_gas_amount;
        self.data_mut().cur_reserved_protocol_fee += additional_gas_amount;
        self.internal_unwrap_mut_btc_pending_info(&original_btc_pending_verify_id)
            .do_cancel(gas_fee, 0);
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L192-204)
```rust
            if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
                self.data_mut().rbf_txs.remove(original_tx_id);
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(original_tx_id);
                let original_tx_btc_pending_info =
                    self.internal_remove_btc_pending_info(original_tx_id);
                let reserved_protocol_fee = original_tx_btc_pending_info.get_max_gas_fee();
                let unused_reserved_protocol_fee =
                    reserved_protocol_fee - btc_pending_info.burn_amount;
                self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
                self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
                self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
```

**File:** contracts/satoshi-bridge/src/rbf/active_utxo_management.rs (L58-68)
```rust
        let max_gas_fee = original_tx_btc_pending_info.get_max_gas_fee();
        let additional_gas_amount = gas_fee.saturating_sub(max_gas_fee);
        require!(additional_gas_amount > 0, "No gas increase.");
        require!(
            self.data().cur_available_protocol_fee >= additional_gas_amount,
            "Insufficient protocol fee"
        );
        self.data_mut().cur_available_protocol_fee -= additional_gas_amount;
        self.data_mut().cur_reserved_protocol_fee += additional_gas_amount;
        self.internal_unwrap_mut_btc_pending_info(&original_btc_pending_verify_id)
            .update_max_gas_fee(gas_fee);
```

**File:** CLAUDE.md (L67-70)
```markdown
### Arithmetic Safety
- **overflow-checks = true:** All overflow panics in release mode (fail-safe)
- Use `checked_mul()`, `checked_add()` for explicit error handling
- Prefer panic over silent
```
