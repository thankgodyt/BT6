### Title
Dust Refund Amount Bypasses `> 0` Threshold, Creating Unrelayable Bitcoin Transaction and Permanently Locking User Funds — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

In `refund_execution_inputs()`, the guard `require!(refund_amount > 0, …)` mirrors the exact off-by-minimum-unit pattern from the external report. When `refund_amount` is above zero but below the Bitcoin dust threshold (analogous to `lotSizeInBase`), the check passes, a dust output is built, MPC signs it, and the transaction is broadcast — but Bitcoin miners reject it as non-standard. Because `execute_refund` already inserted the UTXO into `verified_deposit_utxo` before the transaction can confirm, the deposit UTXO is permanently locked with no on-chain recovery path.

---

### Finding Description

`refund_execution_inputs()` computes the net amount the user receives:

```rust
// contracts/satoshi-bridge/src/refund.rs  L280-L284
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
require!(refund_amount > 0, "Refund amount is zero after gas fee");
``` [1](#0-0) 

The only guard is `> 0`. There is no check that `refund_amount` meets the bridge's own minimum output floor (`min_change_amount`) or Bitcoin's protocol-level dust limit (~546 sat for P2PKH). The upstream gate in `request_refund_callback` is equally weak — it only verifies `gas_fee < amount`, not that `amount − gas_fee` is spendable:

```rust
// contracts/satoshi-bridge/src/refund.rs  L549-L553
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [2](#0-1) 

`execute_refund` is publicly callable (no role restriction beyond the pause guard) and immediately writes the UTXO into `verified_deposit_utxo` inside `finalize_refund_with_psbt` — before any on-chain confirmation:

```rust
// contracts/satoshi-bridge/src/refund.rs  L377-L380
// Mark UTXO as verified to prevent verify_deposit later
self.data_mut()
    .verified_deposit_utxo
    .insert(utxo_storage_key.clone());
``` [3](#0-2) 

The config defines `min_change_amount` as the minimum value a BTC output must carry, but this bound is never applied to the refund output:

```rust
// contracts/satoshi-bridge/src/config.rs  L76-L78
// The minimum value requirement that change address must satisfy in BTC transaction.
#[serde(with = "u128_dec_format")]
pub min_change_amount: u128,
``` [4](#0-3) 

**Attack path (no privileged access required):**

1. User deposits `X` satoshis where `gas_fee < X < gas_fee + min_change_amount` to the bridge deposit address.
2. `verify_deposit` rejects the deposit because `X < min_deposit_amount` — no nBTC is minted.
3. User (or anyone) calls `request_refund`. `request_refund_callback` only checks `gas_fee < X` — passes.
4. After the timelock elapses, any unprivileged account calls `execute_refund`.
5. `refund_execution_inputs` computes `refund_amount = X − gas_fee` (dust, e.g. 1 sat). The `> 0` check passes.
6. `finalize_refund_with_psbt` inserts the UTXO into `verified_deposit_utxo` and creates a `BTCPendingInfo` with a dust output.
7. MPC signs the dust transaction; it is broadcast to Bitcoin but rejected by every miner as non-standard.
8. The UTXO is permanently marked verified — `verify_deposit` is blocked — and the refund transaction can never confirm. The user's BTC is irrecoverably locked.

There is no contract function to remove an entry from `verified_deposit_utxo`, so recovery requires a full contract upgrade.

---

### Impact Explanation

Permanent locking of user funds. The deposit UTXO is unspent on Bitcoin (the dust transaction never confirms) but the bridge treats it as consumed. The user cannot deposit, cannot refund, and cannot recover their BTC without a DAO-initiated contract upgrade. This matches the allowed critical impact: *"Significant loss, theft, destruction, or permanent locking of user or protocol funds."*

---

### Likelihood Explanation

Medium-to-high. The scenario requires only that a deposit amount falls in the narrow window `(gas_fee, gas_fee + min_change_amount)`. With a typical `max_btc_gas_fee` of several thousand satoshis and a `min_change_amount` of similar magnitude, this window is reachable by any user who deposits a small amount that fails `verify_deposit`. No privileged access, no key compromise, and no external dependency failure is needed — only a public call to `request_refund` followed by `execute_refund` after the timelock.

---

### Recommendation

**In `request_refund_callback`** (earliest rejection point, before storage is written):

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
// Add:
require!(
    amount - resolved_gas_fee >= config.min_change_amount,
    "Refund amount after gas fee is below minimum output threshold"
);
```

**In `refund_execution_inputs`** (defence-in-depth):

```rust
// Replace:
require!(refund_amount > 0, "Refund amount is zero after gas fee");
// With:
require!(
    refund_amount >= config.min_change_amount,
    "Refund amount after gas fee is below minimum output threshold"
);
```

---

### Proof of Concept

Assume:
- `config.max_btc_gas_fee` = 5 000 sat (default gas fee for refunds)
- `config.min_change_amount` = 1 000 sat
- `config.min_deposit_amount` = 10 000 sat

1. User sends 5 500 sat to their bridge deposit address.
2. Relayer calls `verify_deposit` → panics: `5 500 < 10 000 = min_deposit_amount`. No nBTC minted.
3. User calls `request_refund(…, gas_fee = None)`. Light-client proof passes. `request_refund_callback` resolves `gas_fee = 5 000`. Check: `5 000 < 5 500` ✓. Request stored with `amount = 5 500`, `gas_fee = 5 000`.
4. After `refund_timelock_sec` seconds, anyone calls `execute_refund`.
5. `refund_execution_inputs`: `refund_amount = 5 500 − 5 000 = 500`. Check: `500 > 0` ✓. Returns `refund_amount = 500`.
6. `finalize_refund_with_psbt` builds a `TxOut { value: 500 sat, script_pubkey: … }`, inserts UTXO into `verified_deposit_utxo`, creates `BTCPendingInfo`.
7. MPC signs; transaction broadcast. Bitcoin nodes reject: output 500 sat < 546 sat dust limit for P2PKH.
8. UTXO permanently locked. User's 5 500 sat are irrecoverable without a contract upgrade.

### Citations

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

**File:** contracts/satoshi-bridge/src/config.rs (L76-78)
```rust
    // The minimum value requirement that change address must satisfy in BTC transaction.
    #[serde(with = "u128_dec_format")]
    pub min_change_amount: u128,
```
