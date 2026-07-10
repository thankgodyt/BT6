### Title
Protocol Fee nBTC Permanently Locked in `acc_protocol_fee_for_gas` With No Withdrawal Path - (File: contracts/satoshi-bridge/src/nbtc/burn.rs)

### Summary
The bridge contract accumulates nBTC tokens into `acc_protocol_fee_for_gas` during active UTXO management and cancel-withdraw RBF operations, but no function exists to withdraw or reclaim these tokens. The `withdraw_protocol_fee` function only drains `cur_available_protocol_fee`, leaving the `acc_protocol_fee_for_gas` balance permanently locked inside the bridge contract.

### Finding Description

The bridge contract maintains five protocol-fee accounting fields:

- `cur_available_protocol_fee` — withdrawable by DAO via `withdraw_protocol_fee`
- `cur_reserved_protocol_fee` — temporarily reserved for pending operations
- `acc_collected_protocol_fee` — lifetime accumulator (informational)
- `acc_claimed_protocol_fee` — lifetime claimed accumulator (informational)
- `acc_protocol_fee_for_gas` — **no withdrawal path exists**

`acc_protocol_fee_for_gas` is incremented in two places:

**Path 1 — Active UTXO management** (`verify_active_utxo_management_burn_callback`):

When an active UTXO management operation completes, `gas_fee` nBTC was previously moved from `cur_available_protocol_fee` → `cur_reserved_protocol_fee`. On success, the callback does:

```rust
self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
```

The `burn_amount` portion of the reserved fee is removed from `cur_reserved_protocol_fee` and added to `acc_protocol_fee_for_gas`. The corresponding nBTC tokens remain physically in the bridge contract but are now unaccounted for in any withdrawable bucket. [1](#0-0) 

**Path 2 — Cancel-withdraw RBF** (`verify_withdraw_burn_callback`):

When a cancel-withdraw RBF is verified and `cancel_rbf_reserved > 0` (the protocol subsidized excess gas from `cur_available_protocol_fee`):

```rust
self.data_mut().cur_reserved_protocol_fee -= cancel_rbf_reserved;
if btc_pending_info.is_cancel_withdraw_rbf() {
    self.data_mut().acc_protocol_fee_for_gas += cancel_rbf_reserved;
}
```

Again, the nBTC tokens are moved out of `cur_reserved_protocol_fee` into `acc_protocol_fee_for_gas` with no withdrawal path. [2](#0-1) 

The only withdrawal function for protocol fees is:

```rust
pub fn withdraw_protocol_fee(&mut self, amount: Option<U128>) -> Promise {
    let total_protocol_fee = self.data().cur_available_protocol_fee;
    let amount = amount.map_or(total_protocol_fee, |v| v.0);
    require!(amount > 0 && amount <= total_protocol_fee, "Invalid amount");
    self.data_mut().cur_available_protocol_fee -= amount;
    ...
}
```

It reads exclusively from `cur_available_protocol_fee` and has no mechanism to touch `acc_protocol_fee_for_gas`. [3](#0-2) 

No other function in the contract decrements `acc_protocol_fee_for_gas` or transfers the corresponding nBTC out. [4](#0-3) 

### Impact Explanation

Every successful active UTXO management operation and every cancel-withdraw RBF where the protocol subsidizes excess gas permanently locks a portion of the protocol fee pool's nBTC inside the bridge contract. These tokens are physically held by the bridge contract (they were never burned or transferred out from the protocol fee pool side), but they are unreachable by any on-chain call. Over time, as the bridge operates normally, `acc_protocol_fee_for_gas` grows monotonically and the locked nBTC balance grows with it. This constitutes permanent locking of protocol funds with no recovery path.

This matches the allowed impact: **Medium — harmful smart-contract behavior without direct funds theft, including stuck bridge state requiring operator intervention**, and also touches **Critical — significant loss or permanent locking of protocol funds**.

### Likelihood Explanation

Active UTXO management (`active_utxo_management`) is a routine operational function called by DAO/Operator to consolidate UTXOs. It is expected to be called regularly as the bridge accumulates UTXOs from user deposits. Every such call that completes successfully contributes to `acc_protocol_fee_for_gas`. The locking is automatic and unconditional — no attacker action is required; normal bridge operation is sufficient. [5](#0-4) 

### Recommendation

Add a withdrawal function for `acc_protocol_fee_for_gas`, or redirect the `burn_amount` portion back to `cur_available_protocol_fee` instead of `acc_protocol_fee_for_gas`. For example, in `verify_active_utxo_management_burn_callback`, replace:

```rust
self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
```

with:

```rust
self.data_mut().cur_available_protocol_fee += btc_pending_info.burn_amount;
self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount; // keep as metric only
```

Or add a DAO-gated `withdraw_protocol_fee_for_gas(amount)` function analogous to `withdraw_protocol_fee` that draws from `acc_protocol_fee_for_gas`.

### Proof of Concept

1. DAO/Operator calls `active_utxo_management` with valid UTXOs. The contract moves `gas_fee` from `cur_available_protocol_fee` → `cur_reserved_protocol_fee`. [6](#0-5) 

2. MPC signs the PSBT; relayer calls `verify_active_utxo_management`. The nBTC burn from the operator's account succeeds.

3. `verify_active_utxo_management_burn_callback` executes: `burn_amount` is subtracted from `cur_reserved_protocol_fee` and added to `acc_protocol_fee_for_gas`. The corresponding nBTC tokens remain in the bridge contract. [7](#0-6) 

4. DAO calls `withdraw_protocol_fee(None)` — it only drains `cur_available_protocol_fee`. The nBTC in `acc_protocol_fee_for_gas` is never transferred and remains locked forever. [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L112-119)
```rust
                    if cancel_rbf_reserved > 0 {
                        self.data_mut().cur_reserved_protocol_fee -= cancel_rbf_reserved;
                        if btc_pending_info.is_cancel_withdraw_rbf() {
                            self.data_mut().acc_protocol_fee_for_gas += cancel_rbf_reserved;
                        } else {
                            self.data_mut().cur_available_protocol_fee += cancel_rbf_reserved;
                        }
                    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L200-214)
```rust
                let unused_reserved_protocol_fee =
                    reserved_protocol_fee - btc_pending_info.burn_amount;
                self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
                self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
                self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
            } else {
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(&tx_id);
                let reserved_protocol_fee = btc_pending_info.get_max_gas_fee();
                let unused_reserved_protocol_fee =
                    reserved_protocol_fee - btc_pending_info.burn_amount;
                self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
                self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
                self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
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

**File:** contracts/satoshi-bridge/src/lib.rs (L141-145)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
```

**File:** contracts/satoshi-bridge/src/btc_light_client/active_utxo_management.rs (L67-82)
```rust
    pub fn create_active_utxo_management_pending_info(
        &mut self,
        account_id: AccountId,
        mut psbt: PsbtWrapper,
    ) {
        self.require_pending_sign_capacity(&account_id);

        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let (actual_received_amount, gas_fee) =
            self.check_active_management_psbt_valid(&psbt, &vutxos);
        require!(
            gas_fee <= self.data().cur_available_protocol_fee,
            "Insufficient protocol_fee"
        );
        self.data_mut().cur_available_protocol_fee -= gas_fee;
        self.data_mut().cur_reserved_protocol_fee += gas_fee;
```
