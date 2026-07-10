### Title
Missing Validation of `refund_address` Before Storage Allows Attacker to Permanently Brick a Refund Request - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

The `refund_address` string supplied to `request_refund` is stored in `RefundRequest` without any validation that it is a syntactically valid BTC address. The only validation occurs later, inside `execute_refund → build_refund_output`, where `Address::parse(...).expect("Invalid refund address")` panics if the address is malformed. Because the panic reverts the call without removing the stored request, the UTXO is permanently stuck in the refund pipeline until a DAO/Operator manually rejects it.

### Finding Description

`internal_request_refund` (the implementation called by the public `request_refund` entry point) performs two checks on `refund_address`:

1. If `deposit_msg.refund_address` is `Some`, it must equal the caller-supplied `refund_address` (line 154–158).
2. The gas fee must be less than the deposit amount (line 550–553).

Neither check validates that `refund_address` is a parseable BTC address for the configured network. [1](#0-0) 

The invalid string is then serialised verbatim into a `RefundRequest` and written to contract storage in `request_refund_callback`: [2](#0-1) 

When `execute_refund` is later called, `build_refund_output` attempts to parse the stored address:

```rust
let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
    .expect("Invalid refund address");   // panics → call reverts
``` [3](#0-2) 

Because the panic reverts the `execute_refund` call without touching `refund_requests`, the request remains in storage with `executed = false`. Every subsequent `execute_refund` call for the same UTXO will panic identically. The UTXO is also not yet in `verified_deposit_utxo` (that only happens inside `finalize_refund_with_psbt`, which is never reached), so the deposit path is also blocked from a clean state perspective.

The `resolve_execute_refund_timelock` comment explicitly acknowledges that when `deposit_msg.refund_address` is `None` the address is "supplied by caller of `request_refund`" and a longer `unsafe_refund_timelock_sec` is applied to give DAO/Operator time to reject suspicious requests — confirming that `request_refund` is reachable by unprivileged callers. [4](#0-3) 

### Impact Explanation

An attacker who front-runs a legitimate user's `request_refund` call (or who is the first to call it for a UTXO whose `deposit_msg.refund_address` is `None`) can supply a syntactically invalid BTC address. The resulting `RefundRequest` can never be executed; `execute_refund` will always panic. The UTXO is stuck in the refund pipeline and the user cannot recover their BTC through the refund flow without DAO/Operator intervention (`reject_refund`). This matches the **Medium** impact class: stuck bridge state requiring operator intervention.

### Likelihood Explanation

All inputs needed to call `request_refund` for a victim's UTXO are public on-chain (Bitcoin transaction bytes, vout, Merkle proof, and the `deposit_msg` used to derive the deposit address). An attacker can observe a pending `request_refund` in the mempool or simply be the first to submit one for any unfinalized deposit whose `deposit_msg.refund_address` is `None`. No privileged access is required.

### Recommendation

Validate `refund_address` as a parseable BTC address for the configured network at the start of `internal_request_refund`, before the Light Client cross-contract call is dispatched:

```rust
// Early validation — fail fast before any async work
crate::network::Address::parse(&refund_address, self.internal_config().chain.clone())
    .unwrap_or_else(|_| env::panic_str("Invalid refund_address"));
```

This mirrors the pattern already used in `build_refund_output` and ensures that an invalid address is rejected synchronously, preventing it from ever reaching contract storage.

### Proof of Concept

1. Alice deposits BTC with `deposit_msg = DepositMsg { refund_address: None, … }`.
2. Attacker observes the deposit on Bitcoin and calls `request_refund` with `refund_address = "not_a_btc_address"` (and a valid proof). The call succeeds; the `RefundRequest` is stored.
3. Alice (or anyone) calls `execute_refund` after the `unsafe_refund_timelock_sec` elapses. `build_refund_output` calls `Address::parse("not_a_btc_address", …).expect(…)` → panic → revert.
4. Every subsequent `execute_refund` call panics identically. Alice's BTC is stuck until DAO/Operator calls `reject_refund`, after which Alice must re-submit a new `request_refund` and wait through the full timelock again. [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-535)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```
