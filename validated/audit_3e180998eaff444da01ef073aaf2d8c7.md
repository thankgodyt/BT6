I need to verify the `require_pending_sign_capacity` check and confirm the full path before concluding.

### Title
Zcash `withdraw_rbf` Missing Fee-Increase Enforcement Allows No-Op RBF Exhaustion of `rbf_num_limit` — (`contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs`)

### Summary

The Zcash implementation of `withdraw_rbf_chain_specific` / `withdraw_rbf_callback` omits the fee-increase guard that the Bitcoin implementation enforces. Combined with `PsbtWrapper::from_original_psbt` silently reusing the original `vout` when `output` is empty, and the Zcash transaction digest including `expiry_height` (which changes on every call), an account owner can repeatedly submit no-op RBFs that produce distinct txids but carry the same fee, consuming the `rbf_num_limit` without ever bumping the fee.

### Finding Description

**Step 1 — Public entrypoint, no role gate.**

`withdraw_rbf` (`api/bridge.rs:259`) is public and only checks `require_pending_sign_capacity`. [1](#0-0) 

**Step 2 — Zcash dispatch schedules an async callback, passing `output` unchanged.**

`withdraw_rbf_chain_specific` (Zcash macro expansion, `zcash_utils/contract_methods.rs:16-35`) fires a cross-contract call to `withdraw_rbf_callback`, forwarding the caller-supplied `output` vec verbatim. [2](#0-1) 

**Step 3 — `from_original_psbt` silently reuses original `vout` when `output` is empty.**

Inside `withdraw_rbf_callback`, `generate_psbt_from_original_psbt_and_new_output` is called with the empty vec. `PsbtWrapper::from_original_psbt` contains the branch:

```rust
let vout = if output.is_empty() {
    original_psbt.vout.clone()   // ← silent fallback
} else { … }
``` [3](#0-2) 

The new PSBT therefore has identical transparent outputs to the original, so the gas fee computed in `check_withdraw_psbt` is identical to the original.

**Step 4 — Zcash `check_withdraw_chain_specific` is a no-op.**

The Bitcoin version enforces `gas_fee > max_gas_fee` ("No gas increase."): [4](#0-3) 

The Zcash override is an empty function: [5](#0-4) 

`internal_withdraw_rbf` calls `Self::check_withdraw_chain_specific(...)` at line 62, but for the Zcash build this call does nothing. [6](#0-5) 

**Step 5 — Different `expiry_height` produces a different txid each call.**

`get_pending_id()` calls `get_zcash_tx().compute_txid()`. The Zcash txid commits to `expiry_height`, which is freshly derived from `last_block_height` on every callback invocation. [7](#0-6) 

So each call produces a unique `btc_pending_id`, bypassing the `"pending info already exist"` and `"Rbf already exist"` guards in `set_rbf_pending_info`. [8](#0-7) 

**Step 6 — `rbf_num_limit` is consumed.**

Each successful `withdraw_rbf_callback` inserts a new entry into `rbf_txs` and increments its length toward `rbf_num_limit`. [9](#0-8) 

**Capacity constraint:** `require_pending_sign_capacity` limits concurrent pending-sign slots (default 1). The attacker must sign each no-op RBF (moving it to PendingVerify, freeing the slot) before issuing the next one. This is feasible because the account owner controls signing via `sign_btc_transaction`. [10](#0-9) 

### Impact Explanation

Once `rbf_num_limit` is exhausted, the contract permanently rejects further `withdraw_rbf` calls for that original pending ID (`"Exceed rbf_num_limit"`). If the original transaction's fee was too low to confirm, the user can no longer accelerate it. The withdrawal remains stuck until an operator calls `cancel_withdraw` after `max_btc_tx_pending_sec` elapses. This is a **stuck bridge state requiring operator intervention** — a Medium-class impact under the allowed scope.

### Likelihood Explanation

The attacker is the account owner of the withdrawal. The path is fully public (no role gate on `withdraw_rbf`). The only cost is NEAR gas for each call and the MPC signing fee for each no-op RBF. The attack is locally reproducible and requires no external conditions beyond having a withdrawal in `PendingVerify` stage.

### Recommendation

1. **Enforce fee increase in the Zcash path.** Replace the no-op `check_withdraw_chain_specific` in `zcash_utils/contract_methods.rs` with the same guard used in the Bitcoin version:
   ```rust
   pub(crate) fn check_withdraw_chain_specific(
       original_tx_btc_pending_info: &BTCPendingInfo,
       gas_fee: u128,
   ) {
       let max_gas_fee = original_tx_btc_pending_info.get_max_gas_fee();
       require!(gas_fee.saturating_sub(max_gas_fee) > 0, "No gas increase.");
   }
   ```

2. **Reject empty `output` in `from_original_psbt` for user-RBF paths.** The silent fallback to original `vout` is appropriate only for internal/cancel paths. For user-initiated RBF, require a non-empty output vec, or explicitly validate that the resulting fee exceeds the original before proceeding.

### Proof of Concept

```
Precondition: user has a Zcash withdrawal in PendingVerify stage with original_id = "X".

Loop N times (N = rbf_num_limit):
  1. Call withdraw_rbf(original_btc_pending_verify_id="X", output=[], chain_specific_data=Some(...))
     → withdraw_rbf_callback fires with fresh last_block_height → new expiry_height
     → from_original_psbt reuses original vout (same fee)
     → check_withdraw_chain_specific is a no-op
     → new RBF entry inserted with unique txid (different expiry_height)
  2. Call sign_btc_transaction on the new RBF pending ID
     → moves it to PendingVerify, frees the pending-sign slot

After N iterations: rbf_txs["X"].len() == rbf_num_limit.
Next call to withdraw_rbf panics: "Exceed rbf_num_limit".
User can no longer bump the fee. Withdrawal is stuck.
```

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

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L214-218)
```rust
    pub(crate) fn check_withdraw_chain_specific(
        _original_tx_btc_pending_info: &BTCPendingInfo,
        _gas_fee: u128,
    ) {
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L117-119)
```rust
        let vout = if output.is_empty() {
            original_psbt.vout.clone()
        } else {
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L431-433)
```rust
    pub fn get_pending_id(self) -> String {
        self.get_zcash_tx().compute_txid().to_string()
    }
```

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

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L57-65)
```rust
        let (actual_received_amount, gas_fee) =
            self.check_withdraw_rbf_psbt_valid(original_tx_btc_pending_info, &withdraw_rbf_psbt);
        btc_pending_info.gas_fee = gas_fee;
        btc_pending_info.actual_received_amount = actual_received_amount;
        btc_pending_info.burn_amount = actual_received_amount + gas_fee;
        Self::check_withdraw_chain_specific(original_tx_btc_pending_info, gas_fee);

        self.internal_unwrap_mut_btc_pending_info(&original_btc_pending_verify_id)
            .update_max_gas_fee(gas_fee);
```

**File:** contracts/satoshi-bridge/src/rbf/mod.rs (L23-41)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        let rbf_txs = self
            .data_mut()
            .rbf_txs
            .entry(original_btc_pending_verify_id.to_owned())
            .or_default();
        require!(rbf_txs.insert(btc_pending_id.clone()), "Rbf already exist");
        if !is_cancel {
            require!(
                rbf_txs.len() <= self.internal_config().rbf_num_limit.into(),
                "Exceed rbf_num_limit"
            );
        }
```

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
```rust
    pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
        require!(
            self.get_account(account_id)
                .unwrap_or_else(|| {
                    env::panic_str(&format!("ERR_ACCOUNT_NOT_REGISTERED: {}", account_id))
                })
                .pending_sign_count()
                < self.get_max_pending_sign_txs(account_id),
            "Too many pending sign transactions"
        );
    }
```
