### Title
Insufficient Refund Gas-Fee Validation Allows Dust Output, Permanently Locking User BTC — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund_callback` only checks `resolved_gas_fee < amount`, mirroring the same class of "check not strong enough" flaw as `_isEnoughIMStrict`. It never verifies that the resulting refund output (`amount − gas_fee`) meets the bridge's own minimum output threshold (`min_change_amount`). An unprivileged caller can submit a refund request with a gas_fee that leaves a sub-dust refund amount. Once `execute_refund` is called, the deposit UTXO is permanently inserted into `verified_deposit_utxo` (blocking `verify_deposit` forever), while the dust refund transaction is rejected by Bitcoin nodes and never confirms — permanently locking the user's BTC with no on-chain recovery path.

---

### Finding Description

**Root cause — `request_refund_callback` (lines 549–553):**

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [1](#0-0) 

The only invariant enforced is `gas_fee < amount`. There is no check that `amount − gas_fee >= config.min_change_amount`. A caller can pass `gas_fee = amount − 1`, leaving a 1-satoshi refund output — well below Bitcoin's dust threshold.

**Secondary weak check — `refund_execution_inputs` (lines 280–284):**

```rust
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
require!(refund_amount > 0, "Refund amount is zero after gas fee");
``` [2](#0-1) 

Again, only `> 0` is checked, not `>= min_change_amount`. This is the exact analog of `_isEnoughIMStrict`: the check is necessary but not sufficient to guarantee the safety invariant (a spendable, non-dust output).

**Irreversible state mutation — `finalize_refund_with_psbt` (lines 377–380):**

```rust
// Mark UTXO as verified to prevent verify_deposit later
self.data_mut()
    .verified_deposit_utxo
    .insert(utxo_storage_key.clone());
``` [3](#0-2) 

`verified_deposit_utxo` is a `LookupSet` with no removal path in any operator-accessible function. Once inserted, `verify_deposit` is permanently blocked for that UTXO. There is no admin function to remove entries from this set. [4](#0-3) 

**Contrast with withdrawal validation** — `check_withdraw_psbt` and `check_psbt_output_all_change_address` both enforce `min_change_amount` and `min_btc_gas_fee` / `max_btc_gas_fee` bounds on every output. The refund path has no equivalent guard. [5](#0-4) 

---

### Impact Explanation

After `execute_refund` is called with a dust gas_fee:

1. The deposit UTXO is permanently in `verified_deposit_utxo` → `verify_deposit` is blocked forever.
2. The refund PSBT carries a sub-dust output → Bitcoin nodes reject the transaction → it never confirms → `verify_refund_finalize` is never callable.
3. `internal_reject_refund` removes only the `refund_requests` entry; it does **not** remove the `verified_deposit_utxo` entry. [6](#0-5) 

The user's BTC is permanently inaccessible through both the deposit and refund paths. This matches the allowed impact: **permanent locking of user funds** / **stuck bridge state requiring operator intervention** (with no operator recovery path once `execute_refund` has run).

---

### Likelihood Explanation

- `request_refund` is a public, permissionless entry point — any NEAR account can call it for any deposit whose `deposit_msg.refund_address` is `None`.
- The caller supplies `gas_fee: Option<u128>` directly; the only server-side guard is `gas_fee < amount`.
- The `unsafe_refund_timelock_sec` (default 14 days) gives the operator a window to reject, but if the operator misses the window (monitoring gap, high request volume, or deliberate timing), the attacker calls `execute_refund` and the state becomes unrecoverable.
- No economic barrier beyond the storage deposit (`required_balance_for_request_refund`) is required. [7](#0-6) 

---

### Recommendation

Add a minimum refund-amount check in `request_refund_callback` immediately after computing `resolved_gas_fee`:

```rust
let config = self.internal_config();
require!(
    amount.saturating_sub(resolved_gas_fee) >= config.min_change_amount,
    "Refund amount after gas fee would be below dust threshold"
);
```

Apply the same guard in `refund_execution_inputs`, replacing `require!(refund_amount > 0, ...)` with `require!(refund_amount >= config.min_change_amount, ...)`.

Additionally, bound `resolved_gas_fee` against `config.max_btc_gas_fee` to match the validation applied in the withdrawal path.

---

### Proof of Concept

1. A user deposits X satoshis to a bridge address derived from a `DepositMsg` with `refund_address: None`.
2. Attacker calls `request_refund` with `gas_fee = Some(X − (min_change_amount − 1))`, providing a valid Merkle proof of the deposit transaction.
3. `request_refund_callback` stores the request: `resolved_gas_fee = X − (min_change_amount − 1)`, check `resolved_gas_fee < X` passes; `refund_amount = min_change_amount − 1` (dust) is never validated.
4. Operator fails to call `reject_refund` within `unsafe_refund_timelock_sec` (14 days).
5. Attacker calls `execute_refund` after the timelock expires.
6. `finalize_refund_with_psbt` inserts the UTXO key into `verified_deposit_utxo` (permanent) and creates a PSBT with a `min_change_amount − 1` satoshi output.
7. The signed refund transaction is broadcast; Bitcoin nodes reject it as dust.
8. `verify_refund_finalize` is never callable (no on-chain inclusion proof exists).
9. `verify_deposit` is permanently blocked by `verified_deposit_utxo`.
10. The user's BTC is permanently locked with no recovery path.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-153)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-553)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
```

**File:** contracts/satoshi-bridge/src/lib.rs (L132-132)
```rust
    pub verified_deposit_utxo: LookupSet<String>,
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L138-142)
```rust
                    require!(
                        u128::from(v.value.to_sat()) >= config.min_change_amount
                            && u128::from(v.value.to_sat()) <= config.max_change_amount,
                        "The output amount is not in the valid range"
                    );
```
