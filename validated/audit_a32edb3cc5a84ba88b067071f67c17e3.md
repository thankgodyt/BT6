### Title
Excess Attached NEAR Deposit Permanently Stuck in Bridge Contract After Successful Refund Request — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
The `internal_request_refund` and `resolve_execute_refund_timelock` functions accept any attached NEAR deposit that meets or exceeds a minimum threshold, but on success they never refund the excess to the caller. Because the NEAR SDK does not automatically return surplus attached deposits, any amount above the minimum is permanently locked in the bridge contract with no recovery path visible in the codebase.

### Finding Description
`internal_request_refund` enforces a lower bound on the attached deposit:

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
``` [1](#0-0) 

The function accepts any value ≥ the minimum. On the success path — after the light-client cross-contract call resolves and `request_refund_callback` stores the `RefundRequest` — no code returns the difference `(attached_deposit − required_balance_for_request_refund())` to the predecessor. The same pattern appears in `resolve_execute_refund_timelock`:

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
``` [2](#0-1) 

Unlike a panic path (where the NEAR runtime automatically refunds the full attached deposit), a successful execution path keeps whatever was attached. The contract has no `withdraw_near`, `recover_near`, or equivalent administrative function visible in the codebase; the only NEAR-denominated withdrawal is `internal_withdraw_protocol_fee`, which operates on nBTC protocol fees, not on the contract's own NEAR balance. [3](#0-2) 

### Impact Explanation
Any NEAR attached above the exact storage minimum is permanently locked in the bridge contract. There is no recovery mechanism. This is a direct analog to the reported vulnerability class: on a successful operation, excess native tokens are silently retained by the contract rather than returned to the sender. The impact is stuck user funds with no path to recovery — qualifying as a stuck-state fault in a production bridge path.

### Likelihood Explanation
Users calling `request_refund` or `execute_refund` through the public API commonly attach a round number or a small buffer above the minimum to guarantee the transaction does not revert due to storage cost fluctuations. Any such overpayment is silently consumed. The entry path is fully unprivileged: any NEAR account can call the public refund entrypoints.

### Recommendation
After the storage deposit is consumed on the success path, compute the surplus and return it to the predecessor:

```rust
let required = self.required_balance_for_request_refund();
let attached = env::attached_deposit();
if attached > required {
    Promise::new(env::predecessor_account_id())
        .transfer(attached.saturating_sub(required));
}
```

Apply the same pattern in `resolve_execute_refund_timelock` (or its callers) using `required_balance_for_execute_refund()`. This mirrors the fix recommended in the external report: refund the remaining balance to the designated refund address after a successful operation.

### Proof of Concept
1. Obtain the value of `required_balance_for_request_refund()` (e.g., 2 NEAR).
2. Call the public `request_refund` entrypoint with `attached_deposit = 3 NEAR` and a valid BTC deposit proof.
3. The light-client verification succeeds; `request_refund_callback` stores the `RefundRequest`.
4. Observe that the bridge contract's NEAR balance increased by 3 NEAR, not 2 NEAR.
5. Attempt to recover the 1 NEAR surplus — no function exists to do so.
6. The 1 NEAR is permanently locked in the bridge contract. [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L202-205)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L11-21)
```rust
    pub fn internal_withdraw_protocol_fee(&self, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .withdraw_protocol_fee_callback(amount.into()),
            )
    }
```
