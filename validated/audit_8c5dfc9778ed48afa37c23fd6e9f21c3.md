### Title
Dust-UTXO Refund Callback Panic Consumes NEAR Storage Deposit Without Creating Refund Request — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

When a user calls `request_refund` with `gas_fee: None` for a dust UTXO, and `config.max_btc_gas_fee` is configured at or above the UTXO's value, the `#[private]` callback `request_refund_callback` panics at the `require!` on lines 550–553. The NEAR storage deposit attached to the original call is consumed by the contract without creating a refund request. The user's BTC dust is not permanently unrefundable (they can retry with an explicit `gas_fee`), but the NEAR storage deposit is irreversibly lost.

---

### Finding Description

`get_refund_gas_fee()` unconditionally returns `config.max_btc_gas_fee`: [1](#0-0) 

In `request_refund_callback`, when the caller passes `gas_fee: None`, the resolved fee is this maximum: [2](#0-1) 

If `max_btc_gas_fee >= deposit_amount` (e.g., `max_btc_gas_fee = 10 000 sats`, dust UTXO = 1 000 sats), the `require!` panics. There is no pre-flight check in `internal_request_refund` that would catch this before the light-client cross-contract call is dispatched: [3](#0-2) 

The original call already transferred the NEAR storage deposit to the contract. When the `#[private]` callback panics, NEAR rolls back only the callback's state changes — the deposit from the original call is not returned.

`max_btc_gas_fee` is a live DAO-updatable config field with no upper-bound constraint relative to any minimum deposit amount: [4](#0-3) [5](#0-4) 

The only constraint is `min_btc_gas_fee < max_btc_gas_fee` — there is no constraint that `max_btc_gas_fee < min_deposit_amount`.

---

### Impact Explanation

- The NEAR storage deposit attached to the `request_refund` call is consumed without creating a refund request.
- No refund request is stored; the UTXO is not added to `verified_deposit_utxo`, so the user can retry — but only if they know to pass an explicit `gas_fee: Some(small_value)`. The "permanently unrefundable" framing in the question is overstated: the BTC is not permanently locked.
- The concrete, irreversible harm is the loss of the NEAR storage deposit on every failed attempt.
- This is a publicly reachable panic-driven fault in a production bridge path, matching the **Low** severity tier.

---

### Likelihood Explanation

- Realistic: Bitcoin gas fees fluctuate widely. A `max_btc_gas_fee` of 10 000–50 000 sats is operationally reasonable during fee spikes, while dust UTXOs (546–2 000 sats) are common for small or mistaken deposits.
- The user-facing API accepts `gas_fee: None` as the natural default; nothing in the documentation or error path before the callback warns the user that the default will exceed their UTXO value.
- No privileged role is required; any account can call `request_refund`.

---

### Recommendation

Add a pre-flight check in `internal_request_refund` (before dispatching the light-client promise) that validates the resolved gas fee against the decoded output value:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
require!(
    resolved_gas_fee < deposit_amount,
    "Gas fee must be less than deposit amount"
);
```

This mirrors the existing check in the callback but fires synchronously before any deposit is consumed, allowing NEAR to return the attached deposit on failure.

---

### Proof of Concept

1. Configure `max_btc_gas_fee = 10_000` (sats).
2. Send a BTC deposit of 5 000 sats to the bridge deposit address.
3. Call `request_refund(..., gas_fee: None)` with the required NEAR storage deposit attached.
4. Light-client verification succeeds; `request_refund_callback` is invoked.
5. `resolved_gas_fee = 10_000 >= amount = 5_000` → `require!` at line 550–553 panics.
6. Callback state is rolled back; no `RefundRequest` is stored.
7. The NEAR storage deposit is not returned to the caller.
8. Retrying with `gas_fee: None` produces the same panic indefinitely; the user must discover they need to pass `gas_fee: Some(0)` or another explicit value.

### Citations

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L10-12)
```rust
    pub(crate) fn get_refund_gas_fee(&self) -> u128 {
        self.internal_config().max_btc_gas_fee
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L146-183)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }

        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-553)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L86-87)
```rust
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
```

**File:** contracts/satoshi-bridge/src/config.rs (L138-141)
```rust
        require!(
            self.min_btc_gas_fee < self.max_btc_gas_fee,
            "min_btc_gas_fee must be less than max_btc_gas_fee"
        );
```
