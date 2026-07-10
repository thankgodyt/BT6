### Title
Unauthenticated `request_refund` Allows Any Caller to Redirect Victim's Deposit Refund to Arbitrary BTC Address — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `request_refund` function performs no caller-identity check against the deposit's intended recipient. When a deposit's `deposit_msg.refund_address` is `None`, any unprivileged NEAR account can submit a refund request for any unverified deposit and supply an arbitrary attacker-controlled BTC address. After `unsafe_refund_timelock_sec` elapses without operator rejection, the attacker calls `execute_refund` and permanently redirects the victim's BTC to themselves.

---

### Finding Description

`request_refund` is publicly callable (no individual `#[trusted_relayer]` attribute, unlike `verify_refund_finalize` and `remove_refund_pending_tx_id` in the same impl block which carry the attribute explicitly). [1](#0-0) 

Inside `internal_request_refund`, the only guard on the caller-supplied `refund_address` is: [2](#0-1) 

When `deposit_msg.refund_address` is `None` this branch is skipped entirely. The caller-supplied address is stored verbatim in the `RefundRequest`: [3](#0-2) 

There is no check that `env::predecessor_account_id()` matches `deposit_msg.recipient_id` or any identity tied to the deposit. The `deposit_msg.recipient_id` field (the NEAR account that should receive minted nBTC) is never compared to the caller. [4](#0-3) 

The longer `unsafe_refund_timelock_sec` is the only mitigation — it gives DAO/Operator time to call `reject_refund`. But `reject_refund` itself requires either a privileged role or the UTXO to already be verified via deposit: [5](#0-4) 

If the operator does not monitor and reject within the timelock window, `execute_refund` is publicly callable by anyone and will dispatch the BTC to the attacker's address: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

If the DAO/Operator fails to reject the malicious request before `unsafe_refund_timelock_sec` expires, the victim's BTC is permanently sent to the attacker's address. This is a direct theft of user funds — a Critical impact under the allowed scope ("Significant loss, theft, destruction, or permanent locking of user or protocol funds"). Even if the operator does intervene, the victim's deposit is temporarily locked and the refund flow is disrupted — a Medium impact ("attacker-triggered temporary locking of bridged funds").

---

### Likelihood Explanation

- Deposits with `deposit_msg.refund_address = None` are the common case (standard deposits, not pre-authorized refund flows).
- The `deposit_msg` is fully derivable from the BTC deposit address, which is public on-chain. An attacker monitoring the Bitcoin mempool/chain can identify unverified deposits and reconstruct the `deposit_msg`.
- The attacker only needs to pay the anti-spam NEAR storage deposit (non-refunded), which is a small cost relative to the BTC value at stake.
- The attack window is the entire period between the BTC deposit landing on-chain and the relayer calling `verify_deposit`. During network congestion or relayer downtime this window can be hours.
- Operator monitoring is not guaranteed to be 24/7 and the `unsafe_refund_timelock_sec` may be set to a value that is too short for reliable human intervention.

---

### Recommendation

Add a caller-identity check in `request_refund` or `internal_request_refund`: when `deposit_msg.refund_address` is `None`, require `env::predecessor_account_id() == deposit_msg.recipient_id`. This mirrors the pattern already used in `withdraw_rbf` / `internal_withdraw_rbf`, where the caller is verified against the stored `account_id` of the pending transaction: [8](#0-7) 

---

### Proof of Concept

1. Alice deposits 500 000 sat to the bridge with `deposit_msg = { recipient_id: "alice.near", refund_address: None, … }`. The relayer has not yet called `verify_deposit`.
2. Bob (attacker) observes the BTC transaction on-chain, derives Alice's `deposit_msg` from the deterministic deposit-address path, and reconstructs `tx_bytes`.
3. Bob calls:
   ```
   request_refund(
       deposit_msg   = { recipient_id: "alice.near", refund_address: None, … },
       refund_address = "bob_btc_address",   // attacker's address
       tx_bytes, vout, proof,
       gas_fee = None
   )
   ```
   with the required NEAR storage deposit attached. No role check fires; the call succeeds and stores `refund_address = "bob_btc_address"` in the `RefundRequest`.
4. The `unsafe_refund_timelock_sec` elapses. The DAO/Operator does not notice or does not act in time.
5. Bob calls `execute_refund(utxo_storage_key, None)`. The bridge builds a refund PSBT sending Alice's 500 000 sat (minus gas fee) to Bob's BTC address and submits it for MPC signing.
6. Alice's BTC is permanently redirected to Bob. Alice receives nothing. [9](#0-8) [10](#0-9)

### Citations

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L544-568)
```rust
    pub fn reject_refund(&mut self, utxo_storage_key: String) {
        let caller = env::predecessor_account_id();
        let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
            || self.acl_has_role(Role::Operator.into(), caller);
        // `execute_refund` also inserts the UTXO into `verified_deposit_utxo` (to block a
        // later deposit) while keeping the request with `executed == true`. That membership
        // must NOT open the permissionless reject path, otherwise anyone could cancel an
        // in-flight refund — so only treat the UTXO as "already deposited" when the request
        // was not executed by us, i.e. a real `verify_deposit` finalized it.
        let executed = self
            .data()
            .refund_requests
            .get(&utxo_storage_key)
            .map(|r| RefundRequest::from(r).executed)
            .unwrap_or(false);
        let is_already_deposited = !executed
            && self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key);
        require!(
            is_privileged || is_already_deposited,
            "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
        );
        self.internal_reject_refund(utxo_storage_key);
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L136-184)
```rust
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

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L43-46)
```rust
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
```
