### Title
Unauthenticated `request_refund` Allows Any Caller to Redirect Unfinalized Deposit BTC to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs, contracts/satoshi-bridge/src/refund.rs)

---

### Summary

`request_refund` contains no check that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`. Any unprivileged NEAR account can submit a refund request for any unfinalized deposit UTXO and supply an arbitrary `refund_address`, causing the bridge's MPC pipeline to send the victim's BTC to the attacker's address once the timelock elapses.

---

### Finding Description

`request_refund` is a public, permissionless function. Its only caller-side guard is an attached-deposit check for storage costs: [1](#0-0) 

The function accepts a `deposit_msg` (which encodes the intended `recipient_id`) and a caller-supplied `refund_address`. It forwards both to `internal_request_refund`: [2](#0-1) 

Inside `request_refund_callback`, the only validation performed is that the output script of the BTC transaction matches the deposit address derived from `deposit_msg`: [3](#0-2) 

There is **no check** that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. The `refund_address` is stored verbatim: [4](#0-3) 

Once stored, `execute_refund` (also permissionless after the timelock) builds a PSBT paying `refund_amount` to that `refund_address` and submits it to the MPC signing pipeline: [5](#0-4) 

The `deposit_msg` used to derive the deposit address is publicly emitted as a NEAR event every time `get_user_deposit_address` is called: [6](#0-5) 

Because `deposit_msg` is public and BTC transactions are on-chain, an attacker has all the inputs needed to construct a valid `request_refund` call for any victim deposit.

---

### Impact Explanation

An attacker who observes an unfinalized deposit (one where `verify_deposit` was never called — e.g., due to relayer downtime) can:

1. Read the victim's `deposit_msg` from the `LogDepositAddress` NEAR event.
2. Obtain the BTC `tx_bytes` from the Bitcoin blockchain.
3. Call `request_refund` with the victim's `deposit_msg` and the attacker's own BTC address as `refund_address`.
4. Wait for `unsafe_refund_timelock_sec` to elapse.
5. Call `execute_refund`; the bridge's MPC pipeline signs and broadcasts a transaction paying the victim's BTC to the attacker's address.

The victim's BTC is permanently transferred to the attacker. This constitutes a **significant theft of user funds**.

The only on-chain mitigation is that DAO/Operator can call `reject_refund` during the timelock window: [7](#0-6) 

However, this is an operational control, not a protocol-level invariant. If the DAO/Operator fails to monitor and reject within `unsafe_refund_timelock_sec`, the theft completes irreversibly.

---

### Likelihood Explanation

- `deposit_msg` is publicly emitted on every deposit address query; no secret knowledge is required.
- BTC transactions are publicly visible on-chain.
- Unfinalized deposits are a realistic scenario (relayer downtime, network congestion, user error).
- The attacker only needs to pay a small NEAR storage deposit to submit the request.
- The race condition favors the attacker: the legitimate depositor may not know about the refund mechanism or may not act within the timelock.
- The duplicate-request guard means the first `request_refund` call wins: [8](#0-7) 

---

### Recommendation

Add an authorization check in `request_refund` (or in `internal_request_refund`) that requires `env::predecessor_account_id()` to equal `deposit_msg.recipient_id`, unless the caller holds a privileged role (DAO/Operator/RefundOperator):

```rust
let caller = env::predecessor_account_id();
let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
    || self.acl_has_role(Role::Operator.into(), caller.clone())
    || self.acl_has_role(Role::RefundOperator.into(), caller.clone());
require!(
    is_privileged || caller == deposit_msg.recipient_id,
    "Only the deposit recipient or a privileged role may request a refund"
);
```

This mirrors the pattern already used in `reject_refund` and `resolve_execute_refund_timelock` for privileged-vs-public caller distinction.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The bridge emits `LogDepositAddress { deposit_msg, deposit_address: "bc1q..." }`.
2. Alice sends 1 BTC to `bc1q...`. The relayer goes offline; `verify_deposit` is never called.
3. Bob (attacker) reads Alice's `deposit_msg` from the NEAR event log and the BTC `tx_bytes` from the Bitcoin blockchain.
4. Bob calls `request_refund(deposit_msg=alice_msg, refund_address="bc1q_bob_addr", tx_bytes=..., vout=0, proof=...)` with the required NEAR storage deposit. The Light Client verifies inclusion; `request_refund_callback` stores the request with `refund_address = "bc1q_bob_addr"`.
5. `unsafe_refund_timelock_sec` elapses without DAO/Operator intervention.
6. Bob calls `execute_refund("txid@0", None)`. The bridge builds a PSBT paying 1 BTC (minus gas fee) to `bc1q_bob_addr` and submits it to MPC for signing.
7. The signed transaction is broadcast; Alice's 1 BTC is permanently transferred to Bob. [9](#0-8) [10](#0-9)

### Citations

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L496-548)
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
