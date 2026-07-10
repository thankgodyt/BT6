### Title
User-Supplied `gas_fee: Some(0)` Bypasses Refund Gas-Fee Policy — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
The `internal_request_refund` function accepts a user-controlled `gas_fee: Option<u128>` parameter. When a caller supplies `Some(0)`, the only validation in `request_refund_callback` — `resolved_gas_fee < amount` — trivially passes, allowing the user to receive a full refund of their deposit with zero gas fee deducted. The configured minimum gas fee (`min_btc_gas_fee`) is never enforced against the caller-supplied value.

### Finding Description
In `contracts/satoshi-bridge/src/refund.rs`, `internal_request_refund` accepts `gas_fee: Option<u128>` directly from the caller and forwards it unchanged into the cross-contract callback: [1](#0-0) 

The callback resolves the fee and applies a single guard: [2](#0-1) 

When the caller passes `gas_fee: Some(0)`, `resolved_gas_fee` is `0`. The check `0 < amount` is always true for any non-dust deposit, so the request is stored with `gas_fee = 0`.

Later, `refund_execution_inputs` computes the refund amount as: [3](#0-2) 

With `gas_fee = 0`, `refund_amount = amount` (the full deposit), and `refund_amount > 0` passes. The bridge then builds and signs a refund transaction returning the entire deposit to the user, paying the on-chain BTC miner fee out of its own UTXO pool with no compensation.

The config defines `min_btc_gas_fee` and `max_btc_gas_fee`: [4](#0-3) 

Neither bound is checked against the caller-supplied `gas_fee` value anywhere in the refund path.

### Impact Explanation
Any user who has made a BTC deposit can request a refund with `gas_fee: Some(0)`, receiving 100% of their deposit back while the bridge absorbs the BTC miner fee for the refund transaction. Repeated use drains the bridge's UTXO pool of fee-covering capacity and forces the operator to subsidize all refund transactions. This is a bypass of the bridge's fee policy.

**Impact: Medium** — Bypass of bridge limits or policies.

### Likelihood Explanation
The entry point is fully public and requires no privilege. Any depositor who wants a refund can trivially pass `gas_fee: Some(0)`. The only prerequisite is a valid BTC deposit and a valid inclusion proof, both of which are normal user actions. Likelihood is **High**.

### Recommendation
In `request_refund_callback` (or in `internal_request_refund` before the cross-contract call), validate the caller-supplied gas fee against the configured minimum:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
let config = self.internal_config();
require!(
    resolved_gas_fee >= config.min_btc_gas_fee,
    "gas_fee below configured minimum"
);
require!(
    resolved_gas_fee <= config.max_btc_gas_fee,
    "gas_fee above configured maximum"
);
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
```

### Proof of Concept

1. Alice deposits 0.01 BTC to her bridge deposit address.
2. Alice calls the public `request_refund` entrypoint with:
   - valid `tx_bytes`, `vout`, `proof` for her deposit transaction
   - `gas_fee: Some(0)`
3. `internal_request_refund` forwards `gas_fee: Some(0)` to `request_refund_callback` with no validation.
4. In the callback, `resolved_gas_fee = 0`. The check `0 < 1_000_000` (satoshis) passes.
5. `RefundRequest` is stored with `gas_fee = 0`, `amount = 1_000_000`.
6. After the timelock, Alice calls `execute_refund`. `refund_execution_inputs` computes `refund_amount = 1_000_000 - 0 = 1_000_000`.
7. The bridge builds a refund PSBT paying Alice the full 1,000,000 satoshis. The BTC miner fee is paid from the bridge's own UTXO inputs, with no deduction from Alice's refund.
8. Alice receives her full deposit; the bridge bears the entire on-chain fee cost. [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L496-553)
```rust
    #[private]
    pub fn request_refund_callback(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        gas_fee: Option<u128>,
    ) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

        // Verify that the output script matches the deposit address derived from deposit_msg
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L83-87)
```rust
    #[serde(with = "u128_dec_format")]
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
```
