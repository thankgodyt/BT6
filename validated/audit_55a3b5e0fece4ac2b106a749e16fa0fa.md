Looking at the bridge's production files for an analog to the M-04 access-control pattern (any caller can invoke a fund-processing function on behalf of another user, enabling front-run DoS or fund redirection).

**Key observations:**

1. `request_refund` is in a `#[trusted_relayer]` impl block but has **no method-level `#[trusted_relayer]`** — unlike `verify_deposit`, `verify_withdraw`, etc. which all carry the method-level attribute. Methods without the method-level attribute are publicly callable (confirmed by `withdraw_rbf`, `claim_lost_found`, `clear_invalid_pending_verify_rbf` in the same block, all using `env::predecessor_account_id()` freely).

2. When `deposit_msg.refund_address` is `None`, the `refund_address` parameter is accepted from the caller without any authentication check.

3. The first `request_refund` for a UTXO wins; subsequent calls fail with "Refund request already exists for this UTXO".

---

### Title
Unauthenticated `request_refund` Allows Attacker to Front-Run and Redirect Victim's BTC Refund — (`contracts/satoshi-bridge/src/api/bridge.rs` / `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`request_refund` is publicly callable by any NEAR account. When the victim's `DepositMsg` has `refund_address: None`, an attacker who observes the victim's pending call can front-run it with the same `deposit_msg` but an attacker-controlled BTC address. The first request wins; the victim's subsequent call is permanently blocked, and the eventual `execute_refund` sends the BTC to the attacker's address.

### Finding Description
`request_refund` sits inside a `#[trusted_relayer]` impl block but carries no method-level `#[trusted_relayer]` attribute, making it publicly callable:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  line 508-535
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,   // ← caller-supplied, no auth check when deposit_msg.refund_address is None
    tx_bytes: Base64VecU8,
    vout: usize,
    proof: TxInclusionProof,
    gas_fee: Option<U128>,
) -> Promise {
```

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
// contracts/satoshi-bridge/src/refund.rs  line 154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

When `deposit_msg.refund_address` is `None` this block is skipped entirely — the caller-supplied `refund_address` is stored verbatim in the `RefundRequest`. The callback then enforces first-writer-wins:

```rust
// contracts/satoshi-bridge/src/refund.rs  line 544-547
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

`execute_refund` is also publicly callable (same impl block, no method-level guard, and the API doc explicitly states "anyone can call `execute_refund`"). After the `unsafe_refund_timelock_sec` elapses, it pays out to whatever `refund_address` was stored.

### Impact Explanation
An attacker who front-runs the victim's `request_refund` achieves two effects simultaneously:

- **DoS (certain):** The victim's own `request_refund` call fails with "Refund request already exists for this UTXO". The victim cannot recover their BTC through the refund path.
- **Theft (conditional):** The stored `RefundRequest` carries the attacker's BTC address. If the DAO/Operator does not reject the request within `unsafe_refund_timelock_sec`, `execute_refund` transfers the victim's BTC to the attacker. The victim permanently loses their deposited BTC.

This matches the allowed impact: *"Significant loss, theft, destruction, or permanent locking of user or protocol funds"* (Critical) and *"attacker-triggered temporary locking of bridged funds"* (Medium). The DoS is unconditional; the theft is conditional on DAO inaction.

### Likelihood Explanation
All inputs the attacker needs are public:
- `deposit_msg` is emitted in the `LogDepositAddress` event when `get_user_deposit_address` is called.
- The BTC transaction (`tx_bytes`, `vout`) is visible on the Bitcoin blockchain.
- NEAR transactions are public and can be monitored in the mempool before finalization.

The attacker only needs to submit a `request_refund` with the same `deposit_msg` and their own BTC address before the victim's transaction is included. The 2 NEAR anti-spam deposit is the only cost.

### Recommendation
Authenticate the caller against the intended recipient. The simplest fix is to require that `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`:

```rust
pub fn request_refund(...) -> Promise {
    if deposit_msg.refund_address.is_none() {
        require!(
            env::predecessor_account_id() == deposit_msg.recipient_id,
            "Only the deposit recipient can request a refund without a pre-authorized refund address"
        );
    }
    ...
}
```

Alternatively, deprecate the `refund_address: None` path and require users to always embed `refund_address` in `DepositMsg` at deposit time (as the pre-authorized path already does).

### Proof of Concept
1. Alice creates `DepositMsg { recipient_id: alice.near, refund_address: None, ... }`, calls `get_user_deposit_address`, and sends 0.01 BTC to the derived address. The `LogDepositAddress` event is emitted with the full `deposit_msg`.
2. Alice submits `request_refund(deposit_msg, alice_btc_addr, tx_bytes, 0, proof)` with 2 NEAR attached.
3. Attacker observes Alice's pending NEAR transaction, extracts `deposit_msg` and `tx_bytes`.
4. Attacker submits `request_refund(deposit_msg, attacker_btc_addr, tx_bytes, 0, proof)` with 2 NEAR, with higher gas priority.
5. Attacker's transaction is included first. `request_refund_callback` stores `RefundRequest { refund_address: attacker_btc_addr, ... }`.
6. Alice's transaction is included next. `request_refund_callback` panics: "Refund request already exists for this UTXO". Alice's 2 NEAR is lost.
7. `unsafe_refund_timelock_sec` elapses. Anyone calls `execute_refund(utxo_storage_key)` with 1 NEAR.
8. `finalize_refund_with_psbt` builds a BTC transaction paying `attacker_btc_addr`. MPC signs it. Alice's 0.01 BTC is transferred to the attacker.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L201-227)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
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
