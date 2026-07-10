### Title
User-Supplied `gas_fee` in Refund Request Bypasses Protocol Minimum Gas Fee Enforcement — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

In `request_refund_callback`, the user-supplied `gas_fee: Option<u128>` parameter is accepted and stored without being validated against the protocol's configured minimum gas fee (`config.min_btc_gas_fee`). A user can supply `gas_fee = Some(0)` (or any arbitrarily small value), bypassing the `get_refund_gas_fee()` default entirely. The resulting refund PSBT is built with a zero-satoshi miner fee, which will never confirm on Bitcoin, while the deposit UTXO is simultaneously marked as verified — permanently locking the funds.

---

### Finding Description

In `request_refund_callback` (refund.rs, line 549):

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
```

The only guard is `resolved_gas_fee < amount`. There is no lower-bound check against `config.min_btc_gas_fee` (which is enforced for withdrawals in `check_withdraw_psbt`). When the user supplies `gas_fee = Some(0)`, `resolved_gas_fee` is `0`, which trivially satisfies `0 < amount`. The value `0` is then stored verbatim in the `RefundRequest`:

```rust
let refund_request = RefundRequest {
    ...
    gas_fee: resolved_gas_fee,   // 0
    ...
};
```

Later, in `refund_execution_inputs` (refund.rs, line 280):

```rust
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)   // amount - 0 = amount
    .expect("Deposit amount too small to cover gas fee");
```

The refund PSBT is built paying the full `amount` to the user and leaving 0 satoshis for miners. This transaction will never confirm on Bitcoin.

Simultaneously, `finalize_refund_with_psbt` marks the UTXO as verified (line 378–380):

```rust
self.data_mut()
    .verified_deposit_utxo
    .insert(utxo_storage_key.clone());
```

This blocks any future `verify_deposit` call for the same UTXO. The stored `gas_fee` cannot be updated after the request is created — re-calling `execute_refund` (permitted when `executed == true`) still reads `refund_request.gas_fee` from storage and produces the same zero-fee PSBT.

This is the direct analog of the reported `optional_royalty_pct` issue: a user-supplied optional parameter is consumed without checking whether a protocol-enforced floor should override it.

---

### Impact Explanation

A user who supplies `gas_fee = Some(0)` causes their deposit UTXO to be:
1. Blocked from `verify_deposit` (UTXO inserted into `verified_deposit_utxo`).
2. Locked in an unconfirmable refund PSBT (0-fee transaction never mined).
3. Irrecoverable — the stored `gas_fee` is immutable after `request_refund_callback`, so every subsequent `execute_refund` re-creates the same unconfirmable transaction.

The deposit funds are permanently stuck. This matches **Medium — attacker-triggered permanent locking of bridged funds** (the user's own deposited BTC/ZEC is irretrievably lost from the bridge's perspective).

---

### Likelihood Explanation

The `gas_fee` parameter is part of the public `request_refund` API, reachable by any unprivileged NEAR account that has made a deposit. No special role or key is required. A user who misunderstands the parameter, or a malicious actor deliberately self-sabotaging to demonstrate the flaw, can trigger this with a single transaction. The missing lower-bound check is a straightforward omission.

---

### Recommendation

In `request_refund_callback`, after resolving `resolved_gas_fee`, add a minimum enforcement analogous to what `check_withdraw_psbt` does for withdrawals:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee >= config.min_btc_gas_fee,
    "Gas fee is below the protocol minimum"
);
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
```

This ensures that any user-supplied value is overridden or rejected when it falls below the protocol-enforced floor, mirroring the remediation described in the external report.

---

### Proof of Concept

1. User deposits BTC to their bridge deposit address; UTXO is recorded on-chain.
2. User calls `request_refund` with `gas_fee: Some(0)` and a valid Merkle proof.
3. `internal_request_refund` passes `gas_fee = Some(0)` to `request_refund_callback`.
4. `resolved_gas_fee = 0`; check `0 < deposit_amount` passes.
5. `RefundRequest { gas_fee: 0, amount: deposit_amount, ... }` is stored.
6. After the timelock, anyone calls `execute_refund`.
7. `refund_execution_inputs` computes `refund_amount = deposit_amount - 0 = deposit_amount`.
8. A PSBT is built: input = deposit UTXO (deposit_amount sat), output = deposit_amount sat to user → miner fee = 0.
9. `finalize_refund_with_psbt` inserts the UTXO key into `verified_deposit_utxo`.
10. The 0-fee transaction is broadcast but never confirmed. `verify_deposit` is permanently blocked. Funds are lost. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
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

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
```rust
        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L252-258)
```rust
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );
```
