### Title
Unauthenticated `request_refund` Allows Any Caller to Redirect BTC Refunds to an Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `request_refund` function in the satoshi-bridge contract accepts a caller-supplied `refund_address` parameter with no check that the caller is the legitimate deposit owner (`deposit_msg.recipient_id`). Any NEAR account can submit a refund request for any deposit UTXO and set an arbitrary BTC destination address. Because only one refund request is permitted per UTXO, a racing attacker can permanently block the legitimate user's refund and, once the `unsafe_refund_timelock_sec` elapses, redirect the BTC to their own address.

---

### Finding Description

**Entry point — `request_refund` (bridge.rs:510–535)**

```rust
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,   // ← fully attacker-controlled when deposit_msg.refund_address is None
    tx_bytes: Base64VecU8,
    vout: usize,
    proof: TxInclusionProof,
    gas_fee: Option<U128>,
) -> Promise {
```

The function carries `#[payable]` and `#[pause(except(roles(Role::DAO)))]` but **no** `#[trusted_relayer]` attribute on the function itself. Every other deposit/withdraw/verify entry point that should be relayer-gated carries the per-function `#[trusted_relayer]` annotation (e.g. `verify_deposit`, `verify_deposit_v2`, `verify_refund_finalize`). `request_refund` is therefore callable by any unprivileged NEAR account.

**Root cause — `internal_request_refund` (refund.rs:137–184)**

The internal implementation performs three checks:

1. Sufficient attached NEAR deposit (storage anti-spam fee).
2. `tx_bytes` size limit.
3. If `deposit_msg.refund_address` is `Some(addr)`, the provided `refund_address` must equal `addr`.

It does **not** check:

```rust
// MISSING:
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Only the deposit recipient can request a refund"
);
```

When `deposit_msg.refund_address` is `None` (the common case for users who did not pre-authorize a BTC return address), the caller's `refund_address` argument is stored verbatim:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // ← stored directly from caller input
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
```

**One-request-per-UTXO exclusion (refund.rs:543–547)**

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

Once an attacker's request is stored, the legitimate user is permanently locked out from submitting their own.

**Execution path — `execute_refund` (bridge.rs:582–589)**

`execute_refund` is also publicly callable (no role restriction). After `unsafe_refund_timelock_sec` elapses, anyone — including the attacker — can call it. The stored `refund_address` is used to build the Bitcoin output and the BTC is sent there.

**Attacker's information requirements**

All inputs needed to craft the attack are public:
- `deposit_msg` — emitted as an on-chain NEAR event by `get_user_deposit_address` (bridge.rs:462–472) and visible in any `verify_deposit` call.
- `tx_bytes` — the raw Bitcoin transaction, publicly available on the Bitcoin blockchain.
- `vout` and `proof` — derivable from the Bitcoin blockchain.

---

### Impact Explanation

**Theft of user BTC (Critical):** If the DAO/Operator does not reject the malicious refund request before `unsafe_refund_timelock_sec` expires, the attacker calls `execute_refund` and the bridge's MPC network signs a Bitcoin transaction paying the attacker's address. The victim's BTC is permanently lost.

**Permanent locking of user funds (Critical/Medium):** Even if the DAO/Operator rejects the malicious request, the attacker can immediately re-submit another one. This creates a griefing loop that keeps the victim's deposit locked indefinitely, requiring continuous operator intervention.

Both outcomes fall within the allowed impact scope:
- *Critical — Significant loss, theft, or permanent locking of user funds.*
- *Medium — Attacker-triggered temporary locking of bridged funds.*

---

### Likelihood Explanation

- **No privilege required.** Any NEAR account can call `request_refund`.
- **All inputs are public.** `deposit_msg`, `tx_bytes`, `vout`, and the Merkle proof are all observable on-chain.
- **Cost is low.** The only barrier is the NEAR storage deposit required by `required_balance_for_request_refund()`, which is a small, recoverable amount.
- **Race window is wide.** The attacker does not need to frontrun a specific transaction; they can submit the malicious request at any time before the legitimate user does, or immediately after a legitimate request is rejected.
- **Mitigation is operator-dependent.** The `unsafe_refund_timelock_sec` is a delay, not a cryptographic guarantee. If the DAO/Operator is slow, offline, or overwhelmed by multiple simultaneous attacks, theft succeeds.

---

### Recommendation

Add a caller-identity check in `internal_request_refund` before storing the request:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Only the deposit recipient can request a refund"
);
```

This mirrors the fix applied in the referenced Celo PR: instead of accepting a critical parameter from an untrusted caller, bind it to a value that only the legitimate owner controls. The `deposit_msg.recipient_id` is already authenticated by the deposit address derivation (the deposit address is the SHA-256 hash of the full `deposit_msg` JSON, so only the true depositor knows the matching `deposit_msg`).

---

### Proof of Concept

1. **Alice** deposits 1 BTC to the bridge with `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The deposit is never finalized (relayer failure or deliberate omission).

2. **Bob** (attacker) observes the `LogDepositAddress` event emitted by `get_user_deposit_address`, recovering the full `deposit_msg`. He fetches `tx_bytes` from the Bitcoin blockchain.

3. Bob calls:
   ```
   request_refund(
       deposit_msg,
       refund_address = "bc1q_bob_address",  // attacker's BTC address
       tx_bytes,
       vout,
       proof,
       gas_fee = None
   )
   ```
   with the required NEAR storage deposit attached.

4. `request_refund_callback` (refund.rs:497–581) verifies the Light Client proof, confirms the output script matches the deposit address, and stores the `RefundRequest` with `refund_address = "bc1q_bob_address"`.

5. Alice attempts to call `request_refund` with her own BTC address. The call panics at refund.rs:544–547: `"Refund request already exists for this UTXO"`.

6. After `unsafe_refund_timelock_sec` seconds pass (assuming DAO/Operator does not reject), Bob calls `execute_refund("txid@vout", None)`.

7. The bridge builds a PSBT spending Alice's deposit UTXO with a single output to `"bc1q_bob_address"`, requests an MPC signature, and broadcasts the transaction. Alice's 1 BTC is sent to Bob. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L563-578)
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
