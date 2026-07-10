### Title
User-Supplied `gas_fee` in Refund Path Lacks Minimum Bound, Enabling Permanently Unconfirmable Refund Transactions - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

The `internal_request_refund` function accepts a caller-supplied `gas_fee: Option<u128>` parameter that is stored in the `RefundRequest` and later used verbatim to construct the Bitcoin refund transaction. The only validation applied is that the fee is strictly less than the deposit amount. No lower-bound check against `config.min_btc_gas_fee` is performed, unlike the regular withdrawal path. A user who supplies `gas_fee = Some(0)` (or any value below the Bitcoin network's minimum relay fee) will have their refund transaction built with an insufficient miner fee, causing it to be permanently unconfirmable and leaving their BTC stuck in the deposit address until an operator intervenes.

### Finding Description

In `contracts/satoshi-bridge/src/refund.rs`, `request_refund_callback` resolves the gas fee as follows:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [1](#0-0) 

The only guard is an upper-bound check (`< amount`). There is no lower-bound check. The value is then stored verbatim in the `RefundRequest`:

```rust
let refund_request = RefundRequest {
    ...
    gas_fee: resolved_gas_fee,
    ...
};
``` [2](#0-1) 

Later, in `refund_execution_inputs`, the stored `gas_fee` is used directly to compute the refund output amount:

```rust
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
require!(refund_amount > 0, "Refund amount is zero after gas fee");
``` [3](#0-2) 

The only check here is that `refund_amount > 0`, meaning `gas_fee = 0` passes (since `amount - 0 = amount > 0`). The resulting Bitcoin transaction will carry a 0-satoshi miner fee and will be rejected by the Bitcoin mempool, never confirming.

By contrast, the regular withdrawal path in `check_withdraw_psbt` enforces both a minimum and maximum gas fee:

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
``` [4](#0-3) 

The refund path has no equivalent lower-bound enforcement, creating an asymmetry in fee validation.

### Impact Explanation

A user who calls `request_refund` with `gas_fee = Some(0)` (or any value below the Bitcoin network's minimum relay fee, typically 1 sat/vbyte) will have a `RefundRequest` stored with an insufficient fee. When `execute_refund` is subsequently called, the bridge constructs and signs a Bitcoin PSBT with a 0-satoshi miner fee. This transaction will be rejected by Bitcoin nodes and never confirm. The user's BTC remains locked in the deposit address indefinitely. Recovery requires operator intervention (DAO or `RefundOperator` role) to reject the existing refund request and create a new one with a valid fee — a stuck bridge state requiring privileged action.

This matches the **Medium** impact: *stuck bridge state requiring operator intervention*.

### Likelihood Explanation

The `gas_fee` parameter is explicitly optional and user-controlled. Any user who calls `request_refund` directly (without going through a frontend that pre-fills the fee) can supply `Some(0)`. The path is fully reachable by any unprivileged NEAR account that has a valid deposit transaction. The likelihood is low-to-medium: accidental misconfiguration is plausible (e.g., a developer testing the API, or a user misreading the parameter as "no fee override"), and the contract provides no guardrail.

### Recommendation

Add a minimum gas fee check in `request_refund_callback`, mirroring the enforcement already present in the withdrawal path:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
require!(
    resolved_gas_fee >= config.min_btc_gas_fee,
    "Gas fee is below the minimum required"
);
``` [1](#0-0) 

This ensures the refund transaction will carry a fee sufficient for Bitcoin network relay and confirmation, consistent with the bounds enforced on the regular withdrawal path.

### Proof of Concept

1. User sends BTC to a deposit address derived from a `DepositMsg`.
2. The deposit fails to meet `min_deposit_amount` or the user simply wants a refund.
3. User calls `request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, gas_fee: Some(0))`.
4. `internal_request_refund` passes the `gas_fee = Some(0)` through to the callback.
5. `request_refund_callback` resolves `resolved_gas_fee = 0`, passes the check `0 < amount`, and stores the `RefundRequest` with `gas_fee: 0`.
6. After the timelock, user calls `execute_refund`. The bridge calls `refund_execution_inputs`, computes `refund_amount = amount - 0 = amount`, passes `refund_amount > 0`, and builds a Bitcoin PSBT paying the full deposit amount to the user with 0 miner fee.
7. The signed transaction is broadcast but rejected by Bitcoin nodes due to insufficient fee.
8. User's BTC remains stuck in the deposit address; recovery requires operator intervention. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-184)
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
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L263-291)
```rust
    /// Parse the original deposit transaction and compute the refund economics.
    pub(crate) fn refund_execution_inputs(
        &self,
        refund_request: &RefundRequest,
    ) -> RefundExecutionInputs {
        let config = self.internal_config();
        let transaction =
            crate::WrappedTransaction::decode(&refund_request.tx_bytes.0, &config.chain)
                .expect("Deserialization tx_bytes failed");
        let txid = transaction.compute_txid();
        let outpoint = OutPoint {
            txid,
            vout: u32::try_from(refund_request.vout)
                .unwrap_or_else(|_| env::panic_str("vout overflow")),
        };
        let deposit_output = transaction.output()[refund_request.vout].clone();

        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");

        RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        }
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
