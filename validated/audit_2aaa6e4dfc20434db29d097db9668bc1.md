### Title
Missing Caller Authorization in `internal_request_refund` Allows Attacker to Redirect Victim's Stuck BTC Refund to Arbitrary Address - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`internal_request_refund` performs no check that the caller is the original depositor. Any unprivileged NEAR account can submit a refund request for any deposit transaction and supply an arbitrary Bitcoin `refund_address`. After `unsafe_refund_timelock_sec` elapses without operator rejection, `execute_refund` can be called by anyone, causing the bridge's MPC key to sign a transaction that pays the victim's BTC to the attacker's address.

### Finding Description
The function `internal_request_refund` in `contracts/satoshi-bridge/src/refund.rs` accepts a caller-supplied `refund_address` and a `deposit_msg` describing any on-chain deposit. When `deposit_msg.refund_address` is `None` (i.e., the depositor did not pre-authorize a refund address), the code only validates that the BTC transaction is included in the chain and that the output script matches the deposit address derived from `deposit_msg`. It never verifies that `env::predecessor_account_id()` has any relationship to the deposit:

```rust
pub(crate) fn internal_request_refund(
    &self,
    deposit_msg: DepositMsg,
    refund_address: String,   // ← attacker-controlled
    tx_bytes: Base64VecU8,
    vout: usize,
    proof: TxInclusionProof,
    gas_fee: Option<u128>,
) -> Promise {
    // ...
    if let Some(msg_refund_address) = &deposit_msg.refund_address {
        require!(
            msg_refund_address == &refund_address,
            "refund_address does not match deposit_msg.refund_address"
        );
    }
    // No check: is env::predecessor_account_id() the depositor?
``` [1](#0-0) 

The stored `RefundRequest` records the attacker-supplied `refund_address` verbatim:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker's BTC address
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [2](#0-1) 

`finalize_refund_with_psbt` later builds a PSBT paying `refund_request.refund_address` and requests an MPC signature, so the signed Bitcoin transaction will pay the attacker:

```rust
let refund_address = refund_request.refund_address.clone();
// ...
Event::RefundExecuted {
    utxo_storage_key: utxo_storage_key.clone(),
    amount: refund_request.amount.into(),
    refund_address,
}.emit();
``` [3](#0-2) 

The only mitigation is `unsafe_refund_timelock_sec`, a configurable delay during which the DAO or `RefundOperator` may call `internal_reject_refund`. If they do not act in time, the attacker calls `execute_refund` and the bridge's MPC key signs a transaction paying the attacker.

### Impact Explanation
A stuck deposit (BTC sent to the bridge but not yet minted, e.g., due to a failed proof submission or a deposit below the confirmation threshold) can be stolen in full. The attacker receives the victim's BTC at their own address; the victim's UTXO is marked `verified_deposit_utxo` after `execute_refund`, permanently blocking any legitimate refund or deposit claim. This is a direct, permanent loss of user funds.

### Likelihood Explanation
The attack requires:
1. A deposit UTXO that is on-chain but not yet minted (stuck deposit). Such UTXOs are observable on the Bitcoin blockchain by anyone.
2. The attacker to submit a valid Merkle inclusion proof — publicly available data.
3. The DAO/`RefundOperator` to fail to reject the request within `unsafe_refund_timelock_sec`.

Stuck deposits occur in normal bridge operation (network congestion, relayer downtime, deposits below confirmation threshold). The proof data is public. The only gate is operator vigilance during the timelock window, which is an operational assumption rather than a cryptographic guarantee.

### Recommendation
Add an authorization check in `internal_request_refund` (or its public API wrapper) that requires `env::predecessor_account_id()` to equal the NEAR account encoded in `deposit_msg` (e.g., `deposit_msg.account_id`), or alternatively require the caller to be a whitelisted relayer or the `RefundOperator` role when no pre-authorized `refund_address` is present in the `deposit_msg`. For the "unsafe" path (no pre-authorized address), the caller should at minimum be the account that originally initiated the deposit, verified against the `deposit_msg` fields.

### Proof of Concept
1. Alice sends 1 BTC to the bridge deposit address derived from her `DepositMsg { account_id: "alice.near", refund_address: None, ... }`. The deposit is on-chain but the relayer fails to submit a mint proof (stuck deposit).
2. Bob observes Alice's deposit transaction on the Bitcoin blockchain and obtains the Merkle inclusion proof.
3. Bob calls the public `request_refund` entry point with Alice's `deposit_msg`, `refund_address = "bob_btc_address"`, and the valid proof. No authorization check prevents this.
4. The bridge stores a `RefundRequest` with `refund_address = "bob_btc_address"`.
5. Bob waits for `unsafe_refund_timelock_sec` to elapse without operator rejection.
6. Bob calls `execute_refund`. The bridge builds a PSBT paying 1 BTC (minus gas fee) to `"bob_btc_address"` and requests an MPC signature.
7. The signed transaction is broadcast; Bob receives Alice's BTC. Alice's UTXO is permanently consumed. [4](#0-3) [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L200-228)
```rust
    /// Zcash `execute_refund` entrypoints.
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
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
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L323-388)
```rust
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

        let deposit_msg = refund_request.deposit_msg();
        let path = get_deposit_path(&deposit_msg);
        let vutxo = VUTXO::Current(UTXO {
            path,
            tx_bytes: refund_request.tx_bytes.0.clone(),
            vout: refund_request.vout,
            balance: u64::try_from(refund_request.amount)
                .unwrap_or_else(|_| env::panic_str("Amount overflow")),
        });

        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

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

        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());

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

```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
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

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```
