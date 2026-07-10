I have all the key code needed to evaluate this claim. Let me trace the exact path.

## Code Trace

**Public entry point** (`api/bridge.rs` → `cancel_active_utxo_management_chain_specific` via the `define_rbf_method!` macro in `bitcoin_utils/contract_methods.rs`) calls `internal_cancel_active_utxo_management`.

**Caller identity check — absent:**

In `internal_active_utxo_management_rbf` (the non-cancel RBF path), there is an explicit ownership check: [1](#0-0) 

In `internal_cancel_active_utxo_management`, that check is entirely absent. The `_account_id` parameter is prefixed with `_` and never used for authorization: [2](#0-1) 

**Gas fee range check — skipped for cancel:**

`check_cancel_active_utxo_management_rbf_psbt_valid` calls `check_psbt_output_all_change_address` with `is_cancel=true`: [3](#0-2) 

Inside `check_psbt_output_all_change_address`, the `min_btc_gas_fee`/`max_btc_gas_fee` range check is gated on `!is_cancel`: [4](#0-3) 

So `gas_fee = input_amount - output_amount` is returned with no upper bound.

**Protocol fee drain:**

Back in `internal_cancel_active_utxo_management`, the unbounded `gas_fee` feeds directly into the protocol fee deduction: [5](#0-4) 

The only guard is `cur_available_protocol_fee >= additional_gas_amount` — which means the attacker can drain up to the entire protocol fee pool in a single call, but not more.

**Output floor constraint (PoC correction):**

The question's PoC says "set output_amount = 1 sat." This is blocked: `force_healthy_output=true` requires every output to satisfy `v.value.to_sat() > config.unhealthy_utxo_amount`: [6](#0-5) 

The attacker cannot set output to 1 sat. However, they can minimize outputs to a single output at `unhealthy_utxo_amount + 1` sats, making `gas_fee = input_amount - (unhealthy_utxo_amount + 1)`. With typical UTXO sizes this is still far above `max_btc_gas_fee`, so the core drain is real even if the exact PoC numbers are off.

**Precondition reachability:**

The original transaction must be in `ActiveUtxoManagementOriginal + PendingVerify` state (i.e., signed by the bridge MPC key) and `max_btc_tx_pending_sec` must have elapsed. Both are normal operational states — any active UTXO management transaction that has been signed but not yet confirmed on-chain satisfies this after the timeout.

---

### Title
Unprivileged caller can drain protocol fee pool via unbounded gas fee in cancel-RBF for active UTXO management — (`contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs`)

### Summary
`internal_cancel_active_utxo_management` omits the caller-ownership check present in every other RBF path, and delegates to `check_psbt_output_all_change_address` with `is_cancel=true`, which skips the `min_btc_gas_fee`/`max_btc_gas_fee` range enforcement. Any account can submit a cancel-RBF PSBT whose gas fee is maximized to `input_amount - (unhealthy_utxo_amount + 1)`, causing `additional_gas_amount` to be arbitrarily large and draining `cur_available_protocol_fee` up to its full balance.

### Finding Description
After a signed active UTXO management transaction has been pending for longer than `max_btc_tx_pending_sec`, any unprivileged account may call the public cancel-RBF entry point with a crafted PSBT. Because:

1. `internal_cancel_active_utxo_management` does not verify `original_tx_btc_pending_info.account_id == caller` (unlike `internal_active_utxo_management_rbf`).
2. `check_psbt_output_all_change_address(…, is_cancel=true)` skips the gas fee range check, returning an unbounded `gas_fee`.
3. `additional_gas_amount = gas_fee.saturating_sub(max_gas_fee)` can be set to any value up to `cur_available_protocol_fee`.
4. The only guard is `cur_available_protocol_fee >= additional_gas_amount`, which the attacker satisfies by choosing `gas_fee = max_gas_fee + cur_available_protocol_fee`.

The entire protocol fee pool is moved from `cur_available_protocol_fee` to `cur_reserved_protocol_fee` in one transaction, and the excess gas fee is ultimately paid to BTC miners (destroyed from the protocol's perspective).

### Impact Explanation
`cur_available_protocol_fee` represents accumulated nBTC protocol revenue used to fund future active UTXO management operations. Draining it to zero permanently destroys that value (paid to BTC miners) and prevents any further protocol-fee-funded operations until the pool is replenished. This is a significant, irreversible loss of protocol funds.

### Likelihood Explanation
The precondition (a signed, timed-out active UTXO management transaction) is a routine operational state. The attack requires no special role, no leaked key, and no coordination — any NEAR account can execute it once the timeout elapses.

### Recommendation
Add a `max_btc_gas_fee` upper bound inside `check_psbt_output_all_change_address` that applies even when `is_cancel=true`, or add a separate explicit cap in `check_cancel_active_utxo_management_rbf_psbt_valid`. Additionally, add the same ownership check present in `internal_active_utxo_management_rbf` to `internal_cancel_active_utxo_management`.

### Proof of Concept
1. Bridge creates an active UTXO management transaction with `input_amount = 10_000_000 sats`, `gas_fee = max_btc_gas_fee` (e.g. 50_000 sats). `cur_available_protocol_fee = P`.
2. Transaction is signed (moves to `PendingVerify`). Set `max_btc_tx_pending_sec = 0`.
3. Attacker calls the public cancel-RBF entry with a PSBT whose single output = `unhealthy_utxo_amount + 1` sats, so `gas_fee ≈ 10_000_000 - unhealthy_utxo_amount - 1`.
4. `additional_gas_amount = gas_fee - max_gas_fee ≈ 9_950_000 sats`.
5. If `P >= additional_gas_amount`, `cur_available_protocol_fee` is reduced by `9_950_000 sats` in one call.
6. Attacker repeats with other timed-out transactions (or the same pattern) until the pool is empty.

#Vulnerability found.

### Citations

**File:** contracts/satoshi-bridge/src/rbf/active_utxo_management.rs (L36-39)
```rust
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L12-18)
```rust
        let (actual_received_amount, gas_fee) = self.check_psbt_output_all_change_address(
            cancel_active_utxo_management_rbf_psbt,
            &original_tx_btc_pending_info.vutxos,
            true,
            true,
        );
        (actual_received_amount, gas_fee)
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L21-27)
```rust
    pub fn internal_cancel_active_utxo_management(
        &mut self,
        _account_id: &AccountId,
        original_btc_pending_verify_id: String,
        cancel_active_utxo_management_rbf_psbt: PsbtWrapper,
        _predecessor_account_id: AccountId,
    ) -> String {
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L54-62)
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
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L131-136)
```rust
                if force_healthy_output {
                    require!(
                        v.value.to_sat() > config.unhealthy_utxo_amount
                            && u128::from(v.value.to_sat()) <= config.max_change_amount,
                        "The output amount is not in the valid range"
                    );
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L152-160)
```rust
        if !is_cancel {
            require!(
                gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
                format!(
                    "Invalid gas fee ({}). valid range: [{}, {}].",
                    gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
                )
            );
        }
```
