### Title
Unchecked User-Supplied `gas_fee` in Refund Request Bypasses Protocol Fee Limits, Causing Depositor Fund Loss - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

Any public NEAR account can call `request_refund` for a failed deposit and supply an arbitrarily high `gas_fee` (up to `amount - 1`). The bridge stores this fee without validating it against the protocol's configured `max_btc_gas_fee` limit. When `execute_refund` is later called, the bridge constructs a Bitcoin refund transaction that pays nearly the entire deposit amount to Bitcoin miners, leaving the depositor with a negligible amount.

### Finding Description

In `request_refund_callback` (`refund.rs`, lines 549–553), the user-supplied `gas_fee` parameter undergoes only a single check:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
```

This allows `gas_fee` to be set to `amount - 1`, leaving only 1 satoshi for the depositor. Critically, the withdrawal path enforces `config.max_btc_gas_fee` in `check_withdraw_psbt` (`psbt.rs`, lines 252–258):

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
```

But the refund path in `refund_execution_inputs` (`refund.rs`, lines 280–284) uses the stored `gas_fee` directly with no such bound:

```rust
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
require!(refund_amount > 0, "Refund amount is zero after gas fee");
```

The `finalize_refund_with_psbt` function then builds the `BTCPendingInfo` and PSBT using this unchecked `gas_fee`, which is signed by MPC and broadcast to Bitcoin. No `max_btc_gas_fee` check exists anywhere in the refund execution path.

### Impact Explanation

A depositor whose BTC deposit failed (e.g., amount below `min_deposit_amount`, or the UTXO was never verified) is entitled to a refund. An attacker who observes the failed deposit on the public Bitcoin blockchain can call `request_refund` with `gas_fee = deposit_amount - 1`. The bridge will then construct and MPC-sign a Bitcoin transaction paying 1 satoshi to the depositor and the rest to miners. The depositor suffers near-total permanent loss of their BTC. This matches the allowed impact: "Significant loss, theft, destruction, or permanent locking of user or protocol funds."

### Likelihood Explanation

Bitcoin transactions are publicly visible. Any NEAR account can call `request_refund` for any failed deposit by supplying the publicly available transaction proof. The attacker does not need any privileged role. The DAO timelock (`refund_timelock_sec` = 2 days for pre-authorized refund addresses, `unsafe_refund_timelock_sec` = 14 days otherwise) provides a window for rejection, but the DAO must actively monitor all refund requests and recognize that a high `gas_fee` is malicious — there is no on-chain enforcement preventing the malicious request from being stored and later executed.

### Recommendation

Enforce the protocol's `max_btc_gas_fee` limit on the user-supplied `gas_fee` in `request_refund_callback`:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
let config = self.internal_config();
require!(
    resolved_gas_fee <= config.max_btc_gas_fee,
    "Gas fee exceeds protocol maximum"
);
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
```

### Proof of Concept

1. Alice sends 0.01 BTC to her deposit address but the amount is below `min_deposit_amount`, so `verify_deposit` will never mint nBTC.
2. Attacker Bob observes Alice's deposit transaction on the Bitcoin blockchain.
3. Bob calls `request_refund(deposit_msg=Alice's, refund_address=Alice's, tx_bytes=..., vout=0, proof=..., gas_fee=Some(999_999))` where Alice's deposit was 1_000_000 satoshis.
4. `request_refund_callback` checks only `999_999 < 1_000_000` → passes. The refund request is stored with `gas_fee = 999_999`.
5. After the timelock, anyone calls `execute_refund`. The bridge computes `refund_amount = 1_000_000 - 999_999 = 1` satoshi.
6. The bridge builds a PSBT paying 1 satoshi to Alice and 999_999 satoshis to Bitcoin miners. MPC signs it.
7. Alice receives 1 satoshi instead of ~1_000_000 satoshis minus a reasonable fee. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-364)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-553)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
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
