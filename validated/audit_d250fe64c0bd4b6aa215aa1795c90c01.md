### Title
Caller-Controlled `gas_fee` in Refund Request Allows Fee Bypass, Causing Permanently Stuck Refund Transactions — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `internal_request_refund` function accepts a caller-supplied `gas_fee: Option<u128>` parameter with no minimum-value validation. A user can pass `gas_fee: Some(0)`, bypassing the protocol-determined gas fee entirely. Because the stored `gas_fee` directly determines the Bitcoin transaction fee (input minus output), a zero gas fee produces an unconfirmable 0-fee Bitcoin transaction. Once `execute_refund` is called, the deposit UTXO is permanently marked as verified in contract state, locking the user's funds with no self-service recovery path.

---

### Finding Description

In `contracts/satoshi-bridge/src/refund.rs`, `internal_request_refund` forwards a caller-supplied `gas_fee` into the async callback: [1](#0-0) 

Inside `request_refund_callback`, the resolved fee is validated only against the deposit amount — there is **no minimum floor**: [2](#0-1) 

The resolved fee is then stored verbatim in the `RefundRequest`: [3](#0-2) 

When `execute_refund` is later called, `refund_execution_inputs` computes the user's payout as `deposit_amount − gas_fee`. With `gas_fee = 0`, the output equals the input, leaving **zero satoshis for miners**: [4](#0-3) 

`finalize_refund_with_psbt` then marks the UTXO as verified to block a future `verify_deposit`, and sets `executed = true`: [5](#0-4) 

Because `gas_fee` is fixed at request time and `execute_refund` always reads it from the stored `RefundRequest`, every subsequent re-execution of the refund also produces a 0-fee transaction. The UTXO is permanently locked in `verified_deposit_utxo` with no on-chain confirmation possible.

---

### Impact Explanation

- The 0-fee Bitcoin transaction will not be mined under normal mempool conditions.
- The deposit UTXO is inserted into `verified_deposit_utxo`, blocking any future `verify_deposit` call for that UTXO.
- The `executed = true` flag allows `execute_refund` to be called again, but the stored `gas_fee = 0` means every re-execution produces the same unconfirmable transaction.
- The user's deposited BTC is permanently inaccessible without privileged contract intervention (DAO upgrade or manual state surgery).
- Matches allowed impact: **Medium — attacker-triggered temporary/permanent locking of bridged funds** (and potentially Critical if the UTXO value is large and operator intervention is unavailable).

---

### Likelihood Explanation

The entry point is publicly reachable by any NEAR account that has sent BTC to a deposit address and whose deposit has not yet been verified. Passing `gas_fee: Some(0)` requires no special role, no leaked key, and no third-party compromise. The `Option<u128>` type of the parameter is specifically designed to be caller-supplied (defaulting to the protocol value only when `None`), confirming the public API exposes it.

---

### Recommendation

Enforce a minimum gas fee floor in `request_refund_callback`, rejecting any caller-supplied value below the protocol minimum:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
let min_gas_fee = self.internal_config().min_btc_gas_fee;
require!(
    resolved_gas_fee >= min_gas_fee,
    "Gas fee below protocol minimum"
);
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
```

Alternatively, remove the caller-supplied `gas_fee` parameter entirely and always derive it from `self.get_refund_gas_fee()`, eliminating the bypass surface completely.

---

### Proof of Concept

1. Attacker sends BTC to a bridge deposit address (deposit fails, e.g. below `min_deposit_amount`).
2. Attacker calls `request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, gas_fee: Some(0))`.
3. `request_refund_callback` stores `RefundRequest { gas_fee: 0, amount: D, ... }` — the only check `0 < D` passes.
4. After the timelock, attacker calls `execute_refund(utxo_storage_key)`.
5. `refund_execution_inputs` computes `refund_amount = D − 0 = D`; the PSBT output equals the input, leaving 0 satoshis as miner fee.
6. `finalize_refund_with_psbt` inserts the UTXO into `verified_deposit_utxo` and sets `executed = true`.
7. The broadcast transaction is never mined. Repeated `execute_refund` calls all produce the same 0-fee PSBT.
8. The deposit UTXO is permanently locked: blocked from `verify_deposit` by `verified_deposit_utxo`, and the refund transaction never confirms on-chain.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-145)
```rust
    pub(crate) fn internal_request_refund(
        &self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<u128>,
    ) -> Promise {
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-401)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
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
