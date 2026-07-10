### Title
Attacker Can Redirect Any Victim's BTC Refund to an Arbitrary Address via `request_refund` - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `request_refund` function is publicly callable by any NEAR account and accepts a caller-supplied `refund_address` (a BTC address) without verifying that the caller is the original depositor. When a deposit's `deposit_msg.refund_address` is `None` — the common case for users who do not pre-authorize a refund address — any unprivileged NEAR account can submit a refund request for any unfinalized BTC deposit and redirect the BTC to an attacker-controlled Bitcoin address.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` is a public, permissionless entry point. It accepts a `deposit_msg` (used to derive and verify the deposit address) and a caller-supplied `refund_address` (the BTC address that will receive the refunded coins). The only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None`, this branch is skipped entirely and the attacker's arbitrary `refund_address` passes through unchecked. [2](#0-1) 

The downstream callback `request_refund_callback` verifies the BTC transaction proof and that the output script matches the deposit address derived from `deposit_msg`, but performs **no check** that the caller is the original depositor. [3](#0-2) 

After the `unsafe_refund_timelock_sec` period elapses, `execute_refund` is also publicly callable by anyone: [4](#0-3) 

The MPC pipeline then signs and broadcasts a Bitcoin transaction paying the attacker-supplied `refund_address`, permanently redirecting the victim's BTC.

The victim's `deposit_msg` is public: `get_user_deposit_address` emits it in a `LogDepositAddress` event, and the BTC transaction bytes and Merkle proof are available from the public Bitcoin blockchain. [5](#0-4) 

---

### Impact Explanation

An attacker who observes any unfinalized deposit (one where `verify_deposit` has not yet been called and `deposit_msg.refund_address` is `None`) can permanently redirect the victim's BTC to an attacker-controlled Bitcoin address. The victim loses their entire deposited BTC with no recourse once the refund transaction is confirmed on-chain. This constitutes direct, irreversible theft of user funds — a critical impact.

---

### Likelihood Explanation

The preconditions are realistic and reachable by any unprivileged NEAR account:

1. **`deposit_msg` is public** — emitted on-chain via `LogDepositAddress` whenever a user calls `get_user_deposit_address`.
2. **Unfinalized deposits exist** — relayer downtime, network congestion, or bugs can leave deposits unfinalized for extended periods.
3. **BTC transaction data is public** — `tx_bytes` and the Merkle proof are available from any Bitcoin node.
4. **The only mitigation is DAO vigilance** — the `unsafe_refund_timelock_sec` window gives the DAO time to call `reject_refund`, but this requires continuous monitoring. If the DAO is offline or slow, the attack succeeds automatically after the timelock. [6](#0-5) 

---

### Recommendation

Bind the refund address at deposit time rather than at refund-request time. Specifically:

- **Require `deposit_msg.refund_address` to be non-`None`** for any deposit that is eligible for a permissionless refund. If no refund address is embedded in the deposit message, only DAO/Operator should be allowed to specify one.
- Alternatively, record `env::predecessor_account_id()` as the refund requester in `RefundRequest` and enforce that only the original requester (or DAO/Operator) can call `execute_refund`. [7](#0-6) 

---

### Proof of Concept

1. Victim calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "victim.near", refund_address: None, ... }`. The contract emits a `LogDepositAddress` event containing the full `deposit_msg`.
2. Victim sends BTC to the returned deposit address.
3. The relayer fails to call `verify_deposit` (e.g., due to downtime).
4. Attacker reads the `deposit_msg` from the on-chain event and fetches the BTC transaction bytes and Merkle proof from the Bitcoin network.
5. Attacker calls `request_refund(deposit_msg, "attacker_btc_address", tx_bytes, vout, proof, None)`. Because `deposit_msg.refund_address` is `None`, the `refund_address` check is skipped and the request is stored with `refund_address = "attacker_btc_address"`.
6. After `unsafe_refund_timelock_sec` elapses (and assuming the DAO does not call `reject_refund`), the attacker calls `execute_refund(utxo_storage_key, None)`.
7. The bridge constructs and MPC-signs a Bitcoin transaction paying `"attacker_btc_address"`, permanently stealing the victim's BTC. [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L32-47)
```rust
pub struct RefundRequest {
    pub deposit_msg_json: String,
    pub utxo_storage_key: String,
    pub tx_bytes: Base64VecU8,
    pub vout: usize,
    pub amount: u128,
    pub refund_address: String,
    pub gas_fee: u128,
    pub created_at_sec: u32,
    /// Set once `execute_refund` has built a refund transaction for this request.
    /// While `true` the request is kept (not removed) so `execute_refund` can be
    /// called again to re-create the transaction (e.g. after a consensus branch
    /// change); it is removed only when the refund is finalized in
    /// `verify_refund_finalize`.
    pub executed: bool,
}
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L510-535)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L582-589)
```rust
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```
