### Title
Unbounded Caller-Supplied `gas_fee` in Refund Requests Allows Near-Total Loss of User Deposit — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `request_refund` flow accepts a caller-supplied `gas_fee` parameter that is validated only to be strictly less than the deposit amount. There is no upper-bound check against `max_btc_gas_fee` or any other configured ceiling. Any unprivileged NEAR account can submit a refund request for a pending deposit with `gas_fee = amount − 1`, leaving the depositor with 1 satoshi (effectively nothing) after the refund executes.

---

### Finding Description

In `request_refund_callback` the resolved gas fee is stored verbatim into the `RefundRequest` with a single guard:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 549-553
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [1](#0-0) 

The only constraint is `resolved_gas_fee < amount`. There is no check against `config.max_btc_gas_fee`, which is the upper bound enforced for every normal withdrawal PSBT:

```rust
// contracts/satoshi-bridge/src/psbt.rs  lines 252-258
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
``` [2](#0-1) 

The stored `gas_fee` is later used directly to compute the amount returned to the user:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 280-284
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
require!(refund_amount > 0, "Refund amount is zero after gas fee");
``` [3](#0-2) 

`refund_amount` is then placed directly into the Bitcoin output sent to the user. [4](#0-3) 

The `max_gas_fee` field stored in the resulting `BTCPendingInfo` is set to the same caller-supplied value, so it provides no independent bound:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 358-362
state: PendingInfoState::Refund(OriginalState {
    stage: PendingInfoStage::PendingSign,
    max_gas_fee: gas_fee,
    ...
}),
``` [5](#0-4) 

---

### Impact Explanation

An attacker who submits a refund request with `gas_fee = deposit_amount − 1` causes the refund Bitcoin transaction to carry a fee of nearly the entire deposit, leaving the depositor with 1 satoshi. The deposit UTXO is then marked as verified on NEAR (blocking any future `verify_deposit`), and the BTC is irrecoverably paid to miners. This constitutes a near-total, permanent loss of the user's bridged funds — matching the "significant loss or permanent locking of user funds" impact tier.

---

### Likelihood Explanation

The attack is reachable by any unprivileged NEAR account. Two deposit classes are vulnerable:

- **`deposit_msg.refund_address = None`** (user did not pre-authorize a refund address): the attacker freely chooses both `refund_address` and `gas_fee`. The `unsafe_refund_timelock_sec` (14 days by default) gives the DAO a window to reject the request, but if the DAO misses it the attack completes. [6](#0-5) 

- **`deposit_msg.refund_address` is set**: the attacker must supply the matching address but can still inflate `gas_fee` to grief the depositor. The shorter `refund_timelock_sec` (2 days) applies, giving the DAO even less time to react. [7](#0-6) 

Deposits that fail verification (wrong amount, wrong address, etc.) are the natural target pool. The attacker pays only NEAR storage deposit and gas.

---

### Recommendation

Cap the caller-supplied `gas_fee` against the protocol's configured maximum:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
require!(
    resolved_gas_fee <= config.max_btc_gas_fee,
    "Gas fee exceeds max_btc_gas_fee"
);
```

This mirrors the bound already enforced for withdrawal PSBTs in `check_withdraw_psbt` and closes the asymmetry between the two code paths.

---

### Proof of Concept

1. User sends 0.01 BTC (1,000,000 satoshis) to the bridge deposit address with `deposit_msg.refund_address = None`. The deposit fails verification (e.g., below `min_deposit_amount`).
2. Attacker calls `request_refund` with `gas_fee = 999_999` and `refund_address = victim_btc_address`, attaching the required NEAR storage deposit.
3. `request_refund_callback` stores `RefundRequest { amount: 1_000_000, gas_fee: 999_999, refund_address: victim_btc_address, ... }`. The only check (`999_999 < 1_000_000`) passes. [8](#0-7) 
4. After `unsafe_refund_timelock_sec` (14 days), attacker calls `execute_refund`. `refund_amount = 1_000_000 − 999_999 = 1` satoshi. A Bitcoin transaction is built paying 1 satoshi to the victim and 999,999 satoshis to miners. [3](#0-2) 
5. The deposit UTXO is marked verified on NEAR, permanently blocking `verify_deposit`. The victim's 0.01 BTC is gone.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-158)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-227)
```rust
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
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

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L358-362)
```rust
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-578)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

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

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
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
