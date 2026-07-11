### Title
Attacker Can Front-Run `request_refund` to Redirect Refund BTC to Attacker-Controlled Address — (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

When `deposit_msg.refund_address` is `None`, any unprivileged NEAR account can call `request_refund` with an arbitrary `refund_address`. Because `request_refund_callback` enforces a first-writer-wins uniqueness constraint on the UTXO key, an attacker who front-runs the victim's call stores a malicious `refund_address` in the shared `refund_requests` map. The victim's call is then permanently rejected with "Refund request already exists for this UTXO," and the victim's BTC is redirected to the attacker's address unless a DAO/Operator manually rejects the malicious request within the `unsafe_refund_timelock_sec` window.

### Finding Description

`request_refund` is publicly callable (no `#[trusted_relayer]` on the function itself, confirmed by tests where `"alice"` — a regular user — calls it successfully). When `deposit_msg.refund_address` is `None`, the `refund_address` parameter is accepted verbatim from the caller with no ownership check:

```rust
// contracts/satoshi-bridge/src/refund.rs:154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

The callback then enforces a uniqueness constraint on the UTXO key:

```rust
// contracts/satoshi-bridge/src/refund.rs:543-547
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [2](#0-1) 

The stored `RefundRequest` permanently records the attacker-supplied `refund_address`:

```rust
// contracts/satoshi-bridge/src/refund.rs:564-574
let refund_request = RefundRequest {
    ...
    refund_address,   // attacker-controlled
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [3](#0-2) 

After `unsafe_refund_timelock_sec` elapses, `execute_refund` is callable by anyone and builds the refund PSBT paying `refund_amount` to the stored `refund_address`:

```rust
// contracts/satoshi-bridge/src/bitcoin_utils/refund.rs:30
let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
``` [4](#0-3) 

**Attack path:**

1. Alice sends BTC to a deposit address derived from `deposit_msg = {recipient_id: alice, refund_address: None}`. Both `deposit_msg` and `tx_bytes` are public (on-chain Bitcoin data + NEAR events from `get_user_deposit_address`).
2. Alice submits `request_refund(deposit_msg, refund_address="alice_btc_addr", tx_bytes, vout, proof)`.
3. Bob observes Alice's pending transaction and submits `request_refund(deposit_msg, refund_address="bob_btc_addr", tx_bytes, vout, proof)` before Alice's is included.
4. Bob's `request_refund_callback` stores `RefundRequest { refund_address: "bob_btc_addr", ... }`.
5. Alice's `request_refund_callback` panics: `"Refund request already exists for this UTXO"`.
6. After `unsafe_refund_timelock_sec`, anyone calls `execute_refund` → BTC is sent to Bob's address.

The only mitigation is DAO/Operator calling `reject_refund` within the timelock window:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs:544-568
pub fn reject_refund(&mut self, utxo_storage_key: String) {
    ...
    require!(
        is_privileged || is_already_deposited,
        "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
    );
``` [5](#0-4) 

However, the DAO/Operator has no on-chain way to verify which `refund_address` is legitimate, making this mitigation unreliable.

### Impact Explanation

**Medium** (escalates to Critical if DAO/Operator fails to intervene). The victim's BTC is temporarily locked — their `request_refund` is permanently rejected and they cannot re-submit until DAO/Operator rejects the malicious request. If the DAO/Operator does not reject within `unsafe_refund_timelock_sec`, the victim's BTC is irreversibly sent to the attacker's Bitcoin address. This matches the allowed impact: *attacker-triggered temporary locking of bridged funds* and, in the failure case, *significant loss or theft of user funds*.

### Likelihood Explanation

**Medium**. All inputs needed for the attack (`deposit_msg`, `tx_bytes`, `vout`, Merkle proof) are publicly observable from Bitcoin chain data and NEAR events. The attacker only needs to submit their `request_refund` before the victim's is finalized. In NEAR Protocol, transaction ordering within a block is validator-controlled, making front-running feasible. The attacker must pay the storage deposit (`required_balance_for_request_refund`), which is a minor cost. The attack only applies when `deposit_msg.refund_address` is `None`.

### Recommendation

1. **Bind `refund_address` to the caller**: Require that the caller of `request_refund` is the `deposit_msg.recipient_id` (the intended nBTC recipient) when `deposit_msg.refund_address` is `None`. This prevents a third party from registering a refund request on behalf of the victim with a malicious address.
2. **Alternatively, require `deposit_msg.refund_address` to always be set**: Enforce that `deposit_msg.refund_address` is `Some` so the refund address is committed at deposit-address-derivation time and cannot be overridden by a front-runner.

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: alice, refund_address: None, ... })` → deposit address emitted in event.
2. Alice sends 100,000 sat to that address; transaction confirmed on Bitcoin.
3. Alice constructs `request_refund(deposit_msg, "alice_btc_addr", tx_bytes, 0, proof)` and submits to NEAR.
4. Bob observes Alice's pending transaction, extracts `deposit_msg`, `tx_bytes`, `proof`, and submits `request_refund(deposit_msg, "bob_btc_addr", tx_bytes, 0, proof)` first.
5. Bob's `request_refund_callback` succeeds; `refund_requests["txid@0"] = { refund_address: "bob_btc_addr", ... }`.
6. Alice's `request_refund_callback` panics: `"Refund request already exists for this UTXO"`.
7. After `unsafe_refund_timelock_sec` elapses, Bob (or anyone) calls `execute_refund("txid@0", None)`.
8. `build_refund_output` pays `refund_amount` to `"bob_btc_addr"`.
9. After MPC signing and broadcast, Alice's 100,000 sat (minus gas fee) is sent to Bob's Bitcoin address. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L30-30)
```rust
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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
