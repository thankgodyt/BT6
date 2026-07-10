### Title
Missing Minimum Refund Output Amount Check Allows Dust Refund Transactions to Be Created and Stuck - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

The `request_refund_callback` function stores a `RefundRequest` without verifying that the net refund amount (`deposit_amount − gas_fee`) meets the Bitcoin dust threshold or the configured `min_change_amount`. The withdrawal path enforces `min_withdraw_amount` on every nBTC transfer, but the refund path only checks `gas_fee < amount` and later `refund_amount > 0`. A deposit whose value sits just above the gas fee but below `min_deposit_amount` will be rejected by `verify_deposit`, yet will pass all refund-path guards and produce a Bitcoin output so small that Bitcoin nodes reject it as non-standard, permanently locking the user's BTC and leaving a stale `BTCPendingInfo` in bridge state that requires operator intervention to clean up.

### Finding Description

**Withdrawal path — check present:** [1](#0-0) 

`ft_on_transfer` enforces `amount >= min_withdraw_amount` before any withdrawal is processed.

**Deposit path — check present:** [2](#0-1) 

`internal_verify_deposit` routes below-minimum deposits to `unavailable_utxo_callback` instead of minting nBTC.

**Refund path — check absent:** [3](#0-2) 

`request_refund_callback` only verifies `resolved_gas_fee < amount`. There is no guard that `amount − gas_fee >= min_change_amount` (or any Bitcoin dust threshold).

Later, `refund_execution_inputs` only checks `refund_amount > 0`: [4](#0-3) 

And `build_refund_output` constructs the Bitcoin output with whatever `refund_amount` is, with no floor: [5](#0-4) 

The `min_change_amount` field exists in `Config` precisely to prevent sub-dust outputs: [6](#0-5) 

but it is never consulted in the refund execution path.

### Impact Explanation

When `refund_amount` is below the Bitcoin dust threshold (~546 sat for P2PKH), the signed refund transaction is broadcast but rejected by Bitcoin nodes as non-standard. The result is:

1. The user's BTC is permanently locked in the bridge's MPC-controlled deposit address.
2. A `BTCPendingInfo` entry remains in bridge state indefinitely (it can never be finalized via `verify_refund_finalize` because the transaction cannot confirm).
3. Cleaning up requires DAO/Operator to call `reject_refund` and then `remove_refund_pending_tx_id`, i.e., explicit operator intervention.

This matches **Medium — stuck bridge state requiring operator intervention**.

### Likelihood Explanation

The vulnerable window is any deposit whose satoshi value satisfies:

```
max_btc_gas_fee  <  deposit_amount  <  min_deposit_amount
```

and where `deposit_amount − max_btc_gas_fee` falls below the Bitcoin dust threshold. With realistic parameters (e.g., `max_btc_gas_fee = 9 000 sat`, `min_deposit_amount = 10 000 sat`), a deposit of 9 001–9 545 sat lands squarely in this window. Any unprivileged NEAR account can call `request_refund` (paying the 2 NEAR anti-spam deposit) and trigger the stuck state. Likelihood is **Low** (requires a specific deposit amount) but the entry path is fully permissionless.

### Recommendation

Add a minimum-output guard in `request_refund_callback` (or in `refund_execution_inputs`) before the `RefundRequest` is stored or the PSBT is built:

```rust
let refund_amount = amount
    .checked_sub(resolved_gas_fee)
    .expect("gas fee exceeds deposit amount");
require!(
    refund_amount >= config.min_change_amount,
    "Refund amount after gas fee is below dust threshold"
);
```

This mirrors the `min_withdraw_amount` guard already present in the withdrawal path and prevents the creation of unbroadcastable refund transactions.

### Proof of Concept

Assume: `max_btc_gas_fee = 9_000 sat`, `min_deposit_amount = 10_000 sat`, Bitcoin P2PKH dust threshold ≈ 546 sat.

1. User sends **9 200 sat** to their bridge deposit address.
2. Relayer calls `verify_deposit` → `internal_verify_deposit` routes it to `unavailable_utxo_callback` (below `min_deposit_amount`). No nBTC is minted.
3. User calls `request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, gas_fee=None)` with 2 NEAR attached.
4. `internal_request_refund` verifies the transaction via the light client, then calls `request_refund_callback`.
5. In `request_refund_callback`: `resolved_gas_fee = get_refund_gas_fee() = 9_000`. Check `9_000 < 9_200` passes. `RefundRequest { amount: 9_200, gas_fee: 9_000 }` is stored.
6. After the timelock, user calls `execute_refund`.
7. `refund_execution_inputs` computes `refund_amount = 9_200 − 9_000 = 200 sat`. Check `200 > 0` passes.
8. `build_refund_output` creates `TxOut { value: 200 sat, script_pubkey: … }`.
9. MPC signs the PSBT. The signed transaction is stored in `BTCPendingInfo`.
10. User broadcasts the transaction. Bitcoin nodes reject it: output value 200 sat < dust limit 546 sat.
11. `verify_refund_finalize` can never succeed. Bridge holds a permanently stale `BTCPendingInfo`; user's 9 200 sat is locked. Operator must intervene to reject and clean up.

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L30-33)
```rust
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L45-51)
```rust
        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
        } else {
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L301-307)
```rust
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
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
