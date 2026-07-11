### Title
Missing Upper-Bound Validation on Caller-Supplied `gas_fee` in Permissionless `request_refund` Enables Griefing Destruction of Depositor Funds - (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

The `request_refund_callback` function in `refund.rs` accepts a caller-supplied `gas_fee` parameter and enforces only a single lower-bound check (`resolved_gas_fee < amount`). There is no upper-bound check against `config.max_btc_gas_fee` or any other ceiling. Because `request_refund` is permissionless — any NEAR account may submit a refund request for any on-chain deposit — an attacker can set `gas_fee` to `amount - 1`, causing the victim's entire deposit to be consumed as a Bitcoin miner fee while the victim receives 1 satoshi.

---

### Finding Description

In `request_refund_callback`, the resolved gas fee is validated only as follows:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [1](#0-0) 

No check against `config.max_btc_gas_fee` (which is enforced for normal withdrawals in `check_withdraw_psbt`) is performed here. [2](#0-1) 

The stored `gas_fee` flows directly into `refund_execution_inputs`, which only checks `refund_amount > 0`:

```rust
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
require!(refund_amount > 0, "Refund amount is zero after gas fee");
``` [3](#0-2) 

And then into `finalize_refund_with_psbt` where `max_gas_fee` is set to the attacker-supplied value with no further validation: [4](#0-3) 

The `request_refund` entry point has no caller-identity check — there is no requirement that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`. When `deposit_msg.refund_address` is `None`, the caller freely supplies any `refund_address`: [5](#0-4) 

This makes the function fully permissionless for deposits that did not pre-authorize a refund address.

---

### Impact Explanation

An attacker who submits a refund request with `gas_fee = deposit_amount - 1` causes the MPC-signed refund transaction to pay 1 satoshi to the `refund_address` and donate the remainder to Bitcoin miners. The victim's deposit is permanently destroyed. This matches the allowed impact: **"Significant loss, theft, destruction, or permanent locking of user or protocol funds."**

---

### Likelihood Explanation

The attack is gated by the `unsafe_refund_timelock_sec` (14 days by default) during which the DAO/Operator can reject the request: [6](#0-5) [7](#0-6) 

However, the DAO rejection is an off-chain, manual, monitoring-dependent control. Any lapse in monitoring (e.g., during a holiday, incident, or governance delay) allows the attack to succeed. The attack is cheap to mount (only requires a NEAR storage deposit) and targets any deposit whose `deposit_msg.refund_address` is `None` — the common case for standard deposits.

---

### Recommendation

Enforce an upper bound on the caller-supplied `gas_fee` in `request_refund_callback`, mirroring the `max_btc_gas_fee` check already applied to normal withdrawals:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
// Add:
require!(
    resolved_gas_fee <= config.max_btc_gas_fee,
    "Gas fee exceeds max_btc_gas_fee"
);
```

Additionally, consider restricting who may submit a refund request for a deposit whose `deposit_msg.refund_address` is `None` (e.g., require the caller to be the `recipient_id` or a whitelisted relayer), analogous to the report's recommendation of making the operation permissioned.

---

### Proof of Concept

1. Alice deposits 500,000 sats to the bridge with a standard `DepositMsg` where `refund_address = None`.
2. The deposit is unprocessable (e.g., below `min_deposit_amount` after a config change).
3. Attacker calls `request_refund` supplying `gas_fee = Some(499_999)` and `refund_address = attacker_btc_address`. The only on-chain check (`499_999 < 500_000`) passes.
4. The `RefundRequest` is stored with `gas_fee = 499_999`.
5. After 14 days, if the DAO has not called `reject_refund`, the attacker calls `execute_refund`.
6. `refund_execution_inputs` computes `refund_amount = 500_000 - 499_999 = 1`. The check `refund_amount > 0` passes.
7. A PSBT is built paying 1 sat to the attacker's address; 499,999 sats become the Bitcoin miner fee.
8. MPC signs the transaction; Alice's 500,000-sat deposit is permanently destroyed. [1](#0-0) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
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

**File:** contracts/satoshi-bridge/src/refund.rs (L358-363)
```rust
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
