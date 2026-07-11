### Title
Missing BTC Address Validation in `request_refund` Enables Attacker-Triggered Temporary Locking of Victim's Refund UTXO - (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

The public `request_refund` entry point accepts any arbitrary string as `refund_address` without validating it as a well-formed BTC address. Because there is no caller-ownership check either, an attacker can front-run a victim's refund request with an invalid `refund_address`. The malicious request passes light-client verification and is stored on-chain. Every subsequent call to `execute_refund` for that UTXO then panics inside `build_refund_output`, permanently blocking the victim's refund until a DAO/Operator manually rejects the attacker's request.

---

### Finding Description

**Step 1 – No address validation at submission time.**

`internal_request_refund` performs three checks before dispatching the light-client promise, but none of them validate that `refund_address` is a parseable BTC address: [1](#0-0) 

The `refund_address` string is forwarded verbatim to the callback.

**Step 2 – Invalid address is stored after light-client success.**

`request_refund_callback` verifies the output script matches the deposit address derived from `deposit_msg`, checks for duplicates, and then unconditionally stores the `RefundRequest` — including the unvalidated `refund_address`: [2](#0-1) 

**Step 3 – `execute_refund` always panics for this request.**

When anyone later calls `execute_refund`, the chain reaches `build_refund_output`, which calls `.expect("Invalid refund address")` on the unparseable string, causing a hard panic and full transaction revert: [3](#0-2) 

The refund request remains in storage with `executed = false`, and the UTXO is not added to `verified_deposit_utxo`.

**Step 4 – Duplicate guard blocks the victim's legitimate request.**

`request_refund_callback` enforces that only one request can exist per UTXO: [4](#0-3) 

While the attacker's malicious request occupies the slot, the victim cannot submit a valid replacement.

**Step 5 – No caller-ownership check.**

`request_refund` is a fully public function with no check that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`: [5](#0-4) 

Any NEAR account can submit a refund request for any UTXO, provided they supply the correct `deposit_msg` (observable from the `LogDepositAddress` event emitted by `get_user_deposit_address`) and pay the non-refundable storage deposit.

---

### Impact Explanation

The victim's BTC UTXO is stuck in the bridge's chain-signatures-controlled deposit address. `execute_refund` reverts on every call. The victim cannot submit a new valid request while the malicious one occupies the slot. Recovery requires a DAO/Operator to call `reject_refund`, after which the victim can re-submit. This matches **Medium – attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention**.

---

### Likelihood Explanation

- The attacker needs the victim's `deposit_msg`, which is publicly emitted via `Event::LogDepositAddress` whenever `get_user_deposit_address` is called.
- The attacker must pay a non-refundable NEAR storage deposit (anti-spam), but this is a one-time cost per targeted UTXO.
- The attack window is the period between the BTC deposit confirming on-chain and the victim calling `request_refund` — a window that can be hours to days for unfinalized deposits.
- No privileged access is required.

---

### Recommendation

Validate `refund_address` as a parseable BTC address for the configured chain inside `internal_request_refund`, before dispatching the light-client verification promise:

```rust
// In internal_request_refund, after the existing checks:
crate::network::Address::parse(&refund_address, self.internal_config().chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This mirrors the validation already present in `build_refund_output` and ensures that any request that passes light-client verification can always be executed.

---

### Proof of Concept

1. Victim deposits BTC to their bridge deposit address (derived from `deposit_msg_victim`). The deposit is never finalized (no `verify_deposit` call).
2. Attacker observes the `LogDepositAddress` event to learn `deposit_msg_victim` and the BTC `tx_bytes`/`vout`.
3. Attacker calls `request_refund(deposit_msg_victim, "INVALID_ADDR", tx_bytes, vout, proof, None)` with sufficient attached NEAR.
4. Light-client verification succeeds (the BTC tx is real). `request_refund_callback` stores `RefundRequest { refund_address: "INVALID_ADDR", executed: false, … }`.
5. Victim calls `request_refund` → reverts: `"Refund request already exists for this UTXO"`.
6. Anyone calls `execute_refund(utxo_storage_key, None)` → panics: `"Invalid refund address"` inside `build_refund_output`.
7. Victim's BTC is locked until DAO calls `reject_refund(utxo_storage_key)`, after which the victim must re-submit with a valid address and pay another storage deposit.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-159)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-300)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
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
