### Title
Missing BTC Address Validation in `request_refund` Allows Permanent Stuck Refund State — (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is a public, unprivileged entry point that accepts an arbitrary `refund_address` string and stores it without validating it as a parseable BTC address. When `execute_refund` is later called, `build_refund_output` calls `Address::parse(...).expect("Invalid refund address")`, which panics on an invalid address, permanently blocking execution. The only resolution is DAO/Operator calling `reject_refund`, and the 2 NEAR storage deposit is non-refundable.

---

### Finding Description

**Step 1 — Public entry, no role gate on `request_refund`.**

`request_refund` sits inside a `#[trusted_relayer] #[near] impl Contract` block, but the `#[trusted_relayer]` attribute on the *impl block* only generates the relayer-management helpers; it does not gate every method in the block. Methods that actually enforce the relayer check carry `#[trusted_relayer]` on the method itself (e.g., `verify_refund_finalize` at line 602, `remove_refund_pending_tx_id` at line 622). `request_refund` has only `#[payable]` and `#[pause]` — no relayer or role check. [1](#0-0) 

**Step 2 — Equality check passes, no format validation.**

`internal_request_refund` checks that `deposit_msg.refund_address` (if set) equals the provided `refund_address`. An attacker who controls the deposit message simply sets both to the same invalid string, satisfying the equality check. No BTC address parsing is attempted here. [2](#0-1) 

**Step 3 — `request_refund_callback` stores the invalid address verbatim.**

After the light-client inclusion proof succeeds, the callback stores a `RefundRequest` with `refund_address` set to the raw, unvalidated string. No address parsing occurs. [3](#0-2) 

**Step 4 — `execute_refund` → `build_refund_output` panics.**

`internal_execute_refund` calls `build_refund_output(&refund_request.refund_address, refund_amount)`. Inside, `Address::parse` returns `Err(...)` for an invalid string, and `.expect("Invalid refund address")` panics, reverting the transaction. This happens every time `execute_refund` is called for this request. [4](#0-3) [5](#0-4) 

**Step 5 — No self-recovery path.**

The only way to remove the stuck request is `reject_refund`, which requires DAO or Operator role (or the UTXO to have been verified via deposit, which it hasn't been). [6](#0-5) 

---

### Impact Explanation

- `execute_refund` permanently panics for the affected UTXO key.
- The 2 NEAR storage deposit attached to `request_refund` is non-refundable by design.
- The deposit UTXO is effectively frozen until DAO/Operator calls `reject_refund`.
- After rejection, a relayer can still call `verify_deposit` to mint nBTC, so the BTC is not permanently destroyed — but the refund path is broken and requires privileged intervention.

Impact: **Medium** — attacker-triggered temporary locking of bridged funds requiring operator intervention, plus permanent loss of the NEAR storage deposit.

---

### Likelihood Explanation

Any account can call `request_refund` with a valid BTC deposit and a `DepositMsg` whose `refund_address` field is set to an arbitrary string. The attacker only needs to:
1. Send BTC to the deposit address derived from a `DepositMsg` containing `refund_address: Some("not_a_btc_address")`.
2. Call `request_refund` with the same `deposit_msg` and `refund_address = "not_a_btc_address"`.

The light-client proof is the only real barrier, and it is satisfied by the attacker's own real BTC deposit. No privileged access is needed.

---

### Recommendation

Validate `refund_address` as a parseable BTC address at the start of `internal_request_refund`, before the light-client cross-contract call is dispatched:

```rust
// In internal_request_refund, after the equality check:
crate::network::Address::parse(&refund_address, self.internal_config().chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This ensures that any address stored in a `RefundRequest` is guaranteed to be parseable when `execute_refund` later calls `build_refund_output`. [7](#0-6) 

---

### Proof of Concept

```rust
// 1. Attacker constructs deposit_msg with an invalid refund address
let deposit_msg = DepositMsg {
    recipient_id: "attacker.near".parse().unwrap(),
    refund_address: Some("not_a_btc_address".to_string()),
    ..Default::default()
};

// 2. Attacker sends BTC to the derived deposit address, then calls:
contract.request_refund(
    deposit_msg.clone(),
    "not_a_btc_address".to_string(), // equality check passes
    tx_bytes,
    vout,
    proof,
    None,
);

// 3. Light client returns true → request_refund_callback stores RefundRequest
//    with refund_address = "not_a_btc_address"

// 4. After timelock elapses, anyone calls execute_refund:
contract.execute_refund(utxo_storage_key, None);
// → build_refund_output → Address::parse("not_a_btc_address", ...) → Err(...)
// → .expect("Invalid refund address") → PANIC
// → Transaction reverts; request is permanently stuck
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L294-298)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L29-31)
```rust
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

```
