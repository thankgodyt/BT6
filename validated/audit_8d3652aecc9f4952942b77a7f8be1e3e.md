The critical code is in `contracts/satoshi-bridge/src/psbt.rs`. Let me trace the exact boundary condition.

### Title
Off-by-One Boundary Exclusion in Passive UTXO Management Constraints Allows Policy Bypass at Exact Limit Values — (`contracts/satoshi-bridge/src/psbt.rs`)

---

### Summary

`check_withdraw_psbt_valid` uses strict `<` / `>` comparisons against `passive_management_lower_limit` and `passive_management_upper_limit`. When `utxo_num` equals either limit exactly, neither branch fires and no passive management constraint is applied. An unprivileged user can exploit this to submit a withdrawal that violates the intended UTXO-ratio policy at the boundary.

---

### Finding Description

The guard in `check_withdraw_psbt_valid` is:

```rust
// psbt.rs lines 56-60
if utxo_num < config.passive_management_lower_limit {
    require!(input_num < change_num, "require input_num < change_num");
} else if utxo_num > config.passive_management_upper_limit {
    require!(input_num > change_num, "require input_num > change_num");
}
``` [1](#0-0) 

`utxo_num` is computed as:

```rust
let utxo_num = self.data().utxos.len() + vutxos_len;
``` [2](#0-1) 

**Critically**, `generate_vutxos` is called *before* `check_withdraw_psbt_valid` in `create_btc_pending_info`:

```rust
// token_receiver.rs lines 79, 90
let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);  // removes inputs from utxos map
...
let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(..., &vutxos, ...);
``` [3](#0-2) 

`generate_vutxos` calls `remove_vutxo_by_psbt`, which removes the input UTXOs from `self.data_mut().utxos` before the check runs: [4](#0-3) 

Therefore at the time of the check:
- `self.data().utxos.len()` = `original_count − input_num`
- `vutxos_len` = `input_num`
- `utxo_num` = `original_count` (the pre-withdrawal total)

When `original_count == passive_management_lower_limit` exactly, the condition `utxo_num < passive_management_lower_limit` is **false** and `utxo_num > passive_management_upper_limit` is also **false** (assuming lower ≤ upper). Neither branch executes. The same gap exists at `passive_management_upper_limit`.

The config fields confirm these are intended as inclusive trigger thresholds:

> *"When the number of UTXOs in the protocol is less than this configuration, passive UTXO management will be triggered…"* [5](#0-4) 

The strict operators exclude the boundary values, contradicting the documented intent.

---

### Impact Explanation

**At `utxo_num == passive_management_lower_limit`:** The policy requires `input_num < change_num` (net UTXO growth). With the constraint skipped, an attacker submits `input_num > change_num`. The post-withdrawal UTXO count drops to `passive_management_lower_limit − (input_num − change_num)`, pushing the pool below the lower limit without the required compensating outputs. Repeated exploitation degrades the pool further.

**At `utxo_num == passive_management_upper_limit`:** The policy requires `input_num > change_num` (net UTXO consolidation). With the constraint skipped, an attacker submits `input_num < change_num`, inflating the pool above the upper limit.

Neither case causes direct fund theft, but the UTXO pool can be driven into a state where future withdrawals cannot be constructed (too few UTXOs available as inputs), constituting attacker-triggered temporary locking of bridged funds — a **Medium** impact under the allowed scope.

---

### Likelihood Explanation

The attacker path is fully public: send nBTC via `ft_transfer_call` with a `Withdraw` message. The attacker only needs to observe the on-chain UTXO count (readable from contract state) and submit when it equals a limit. No privileged role is required. The boundary is a single integer equality, reachable in normal bridge operation whenever deposits or prior withdrawals bring the count to exactly the limit value.

---

### Recommendation

Change the strict comparisons to inclusive ones to match the documented semantics:

```rust
if utxo_num <= config.passive_management_lower_limit {
    require!(input_num < change_num, "require input_num < change_num");
} else if utxo_num >= config.passive_management_upper_limit {
    require!(input_num > change_num, "require input_num > change_num");
}
``` [1](#0-0) 

---

### Proof of Concept

1. Configure: `passive_management_lower_limit = 5`, `passive_management_upper_limit = 20`.
2. Ensure the bridge has exactly **5 UTXOs** in `data().utxos`.
3. As an unprivileged user, call `ft_transfer_call` on the nBTC contract with a `Withdraw` message whose PSBT uses **2 inputs** and produces **1 change output** (`input_num=2 > change_num=1`).
4. Inside `create_btc_pending_info`:
   - `generate_vutxos` removes 2 UTXOs → `data().utxos.len() = 3`
   - `check_withdraw_psbt_valid` computes `utxo_num = 3 + 2 = 5`
   - `5 < 5` → false; `5 > 20` → false → **no constraint applied**
5. The withdrawal is accepted. Post-withdrawal UTXO count = `5 − 2 + 1 = 4`, below the lower limit, with no compensating growth enforced.
6. Assert: the passive management constraint (`input_num < change_num`) was **not** enforced despite `utxo_num` being at the lower limit.

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L21-24)
```rust
        let vutxos_len = u32::try_from(vutxos.len()).unwrap_or_else(|_| {
            env::panic_str("vutxos len overflow");
        });
        let utxo_num = self.data().utxos.len() + vutxos_len;
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L56-60)
```rust
        if utxo_num < config.passive_management_lower_limit {
            require!(input_num < change_num, "require input_num < change_num");
        } else if utxo_num > config.passive_management_upper_limit {
            require!(input_num > change_num, "require input_num > change_num");
        }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L79-98)
```rust
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );

        let withdraw_change_address_script_pubkey =
            self.internal_config().get_change_script_pubkey();
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );
```

**File:** contracts/satoshi-bridge/src/utxo.rs (L61-77)
```rust
    pub fn remove_vutxo_by_psbt(&mut self, psbt: &PsbtWrapper) -> (Vec<String>, Vec<VUTXO>) {
        let mut utxo_storage_keys = vec![];
        let vutxos = psbt
            .get_utxo_storage_keys()
            .into_iter()
            .map(|utxo_storage_key| {
                utxo_storage_keys.push(utxo_storage_key.clone());
                self.data_mut()
                    .utxos
                    .remove(&utxo_storage_key)
                    .unwrap_or_else(|| {
                        env::panic_str(&format!("UTXO {} not exist", utxo_storage_key))
                    })
            })
            .collect::<Vec<_>>();
        (utxo_storage_keys, vutxos)
    }
```

**File:** contracts/satoshi-bridge/src/legacy.rs (L118-123)
```rust
    // When the number of UTXOs in the protocol is less than this configuration, passive UTXO management will be triggered,
    // requiring that the number of inputs must be less than the number of changes.
    pub passive_management_lower_limit: u32,
    // When the number of UTXOs in the protocol is greater than this configuration, passive UTXO management will be triggered,
    // requiring that the number of inputs must be greater than the number of changes.
    pub passive_management_upper_limit: u32,
```
