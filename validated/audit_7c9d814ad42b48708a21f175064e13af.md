### Title
Excess Attached NEAR Deposit Not Refunded in Refund Storage-Deposit Checks - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
The `internal_request_refund` and `resolve_execute_refund_timelock` functions in the satoshi-bridge contract use a non-strict `>=` comparison when validating the caller's attached NEAR deposit. Any NEAR attached above the required minimum is silently absorbed by the contract and never returned to the caller.

### Finding Description
Both refund entry-points gate execution on a minimum attached deposit for on-chain storage costs:

`internal_request_refund` (called by the public `request_refund` extrinsic):

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
```

`resolve_execute_refund_timelock` (called by the public `execute_refund` extrinsic):

```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
```

Neither function computes `excess = attached - required` and issues a `Promise::new(env::predecessor_account_id()).transfer(excess)` to return the surplus. In NEAR Protocol, any yoctoNEAR attached to a call that is not explicitly transferred out remains in the contract's balance permanently. There is no storage-withdrawal mechanism in the bridge contract that would allow the caller to reclaim the overpayment later.

The required balance for `request_refund` is sized to cover up to ~200 KB of on-chain storage (≈ 2 NEAR per the inline comment), making the per-call overpayment potentially significant. [1](#0-0) [2](#0-1) 

### Impact Explanation
Any unprivileged user who calls `request_refund` or `execute_refund` with an attached deposit larger than the exact required amount permanently loses the excess NEAR to the contract. The contract has no mechanism to return or track the overpayment. This constitutes a publicly reachable permanent loss of user funds on a production bridge path.

**Allowed impact matched:** *Low — Publicly reachable invariant-violation / stuck-state in production bridge paths without direct theft.*

### Likelihood Explanation
Likelihood is low-to-medium. The required balance is a view-method return value (`required_balance_for_request_refund`, `required_balance_for_execute_refund`). Users or integrators who round up, use a safety margin, or misread the required amount will silently lose the difference. The refund flow is a user-facing, permissionless path reachable by any NEAR account holder. [3](#0-2) 

### Recommendation
After the minimum-deposit guard, compute and return any surplus to the caller:

```rust
let required = self.required_balance_for_request_refund();
let attached = env::attached_deposit();
require!(attached >= required, "Insufficient deposit for storage");
let excess = attached.saturating_sub(required);
if excess > NearToken::from_yoctonear(0) {
    Promise::new(env::predecessor_account_id()).transfer(excess);
}
```

Apply the same pattern in `resolve_execute_refund_timelock`. Alternatively, enforce strict equality (`==`) so callers must supply the exact amount, preventing silent loss.

### Proof of Concept

1. Query `required_balance_for_request_refund()` → returns `R` yoctoNEAR (e.g., 2 NEAR).
2. Call `request_refund(...)` with `attached_deposit = R + 1_000_000_000_000_000_000_000_000` (1 extra NEAR).
3. The `>=` guard passes; the function proceeds normally.
4. No transfer of the 1 NEAR surplus is issued anywhere in `internal_request_refund` or its callback `request_refund_callback`.
5. The caller's account is debited the full `R + 1 NEAR`; the contract balance increases by `R + 1 NEAR`; the 1 NEAR overpayment is permanently unrecoverable. [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L14-27)
```rust
pub(crate) const GAS_FOR_REQUEST_REFUND_CALLBACK: Gas = Gas::from_tgas(20);
pub(crate) const GAS_FOR_VERIFY_REFUND_CALLBACK: Gas = Gas::from_tgas(20);

/// Upper bound on the deposit `tx_bytes` accepted by `request_refund`.
///
/// The RefundRequest stores `tx_bytes` verbatim (no truncation — `execute_refund`
/// later decodes them to rebuild the refund tx), so storage grows ~1:1 with tx size:
/// at this cap a request stores ~200 KB ≈ 2 NEAR, which `required_balance_for_request_refund`
/// is sized to cover. The cap also sits safely below the hard gas ceiling: decoding +
/// borsh-storing the tx happens in `request_refund_callback` (only 20 Tgas), which runs
/// out of gas around ~250 KB regardless of the attached deposit. 200 KB is ~1350 signed
/// P2PKH inputs — far above any real deposit (1-2 inputs), incl. large consolidations.
pub(crate) const MAX_REQUEST_REFUND_TX_BYTES: usize = 200_000;

```

**File:** contracts/satoshi-bridge/src/refund.rs (L132-184)
```rust
impl Contract {
    /// Submit a refund request. Verifies the BTC transaction via Light Client first.
    /// If `deposit_msg.refund_address` is set, it must match the provided `refund_address`.
    /// If `deposit_msg.refund_address` is None, the provided `refund_address` is used.
    #[allow(clippy::too_many_arguments)]
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

**File:** contracts/satoshi-bridge/src/refund.rs (L201-205)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-581)
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

        true
    }
```
