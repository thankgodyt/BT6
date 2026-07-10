Looking at the exact code path in `contracts/satoshi-bridge/src/refund.rs` and `contracts/satoshi-bridge/src/api/bridge.rs`.

**Key guard — `internal_request_refund` (refund.rs:154-159):**

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

When `deposit_msg.refund_address` is `None`, the entire check is skipped. The caller-supplied `refund_address` is stored verbatim in the `RefundRequest`.

**Access control on `request_refund`:**

The `#[trusted_relayer]` attribute on the impl block at bridge.rs:480 generates whitelist-management helpers; it does not gate `request_refund` itself. Tests `test_refund_no_refund_address` and `test_refund_address_none_in_deposit_msg` both call `request_refund` as "alice" (a regular, unprivileged NEAR account) and succeed. The only cost is the attached NEAR storage deposit.

**Deposit-address binding check (refund.rs:517-525):**

```rust
let path = get_deposit_path(&deposit_msg);
let deposit_address = self.generate_utxo_chain_address(&path);
require!(deposit_script_pubkey == output.script_pubkey, ...);
```

This verifies the BTC output matches the address derived from the supplied `deposit_msg`. An attacker who supplies the *exact same* `deposit_msg` (with `refund_address: None`) passes this check, because the deposit address was derived from that same message.

**Information availability:**

`get_user_deposit_address` emits a `LogDepositAddress` event containing the full `deposit_msg` (bridge.rs:465-470), making `recipient_id` and the `refund_address: None` flag publicly observable on NEAR. The BTC `tx_bytes` and `vout` are public on the Bitcoin chain.

**Documented but still exploitable:**

The doc comment at bridge.rs:494-497 and refund.rs:134-135 explicitly states this behavior. However, documentation of a design choice does not eliminate the security impact: a depositor who omitted `refund_address` from their `deposit_msg` has no on-chain mechanism to reclaim control of the refund destination after the fact.

**DAO rejection as the only mitigation:**

The DAO can call `reject_refund` to cancel a malicious request (shown in `test_zcash_refund_reject`). This is a purely operational/governance control — it requires the DAO to actively monitor every refund request and act within the timelock window. It is not a cryptographic or code-level invariant.

---

### Title
Unprivileged caller can redirect BTC refund to attacker-controlled address when `deposit_msg.refund_address` is `None` — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
When a depositor obtains a bridge deposit address without embedding a `refund_address` in their `DepositMsg`, any unprivileged NEAR account can call `request_refund` with an attacker-controlled BTC address. The only guard that enforces address ownership is skipped when `deposit_msg.refund_address` is `None`, so the stored `RefundRequest.refund_address` becomes the attacker's address, and the eventual MPC-signed refund transaction sends the BTC there.

### Finding Description
`internal_request_refund` (refund.rs:154-159) contains a conditional guard:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(msg_refund_address == &refund_address, ...);
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None`, the `if let` arm is never entered, and the caller-supplied `refund_address` string is forwarded unchecked to `request_refund_callback`, where it is stored directly in the `RefundRequest`: [2](#0-1) 

The only other check in the callback verifies that the BTC output's `script_pubkey` matches the deposit address derived from the supplied `deposit_msg`: [3](#0-2) 

An attacker who supplies the *identical* `deposit_msg` (with `refund_address: None`) passes this check trivially, because the deposit address was derived from that same message. The `deposit_msg` is fully public: `get_user_deposit_address` emits a `LogDepositAddress` event containing it: [4](#0-3) 

`request_refund` is publicly callable (no role gate beyond the NEAR storage deposit): [5](#0-4) 

### Impact Explanation
After the `unsafe_refund_timelock_sec` elapses, the stored `refund_address` is used to build and MPC-sign a BTC transaction. If the attacker's address is stored, the BTC is sent to the attacker. The depositor loses their entire deposit with no on-chain recourse. This is direct, permanent theft of user funds — Critical impact.

### Likelihood Explanation
All inputs required for the attack are public:
- `deposit_msg` (including `recipient_id` and `refund_address: None`) is emitted as a NEAR event by `get_user_deposit_address`.
- `tx_bytes` and `vout` are visible on the Bitcoin blockchain.

The attacker pays only the NEAR storage deposit (a small, fixed amount). The attack window is the entire period between the BTC deposit confirmation and the `verify_deposit` finalization call. Any deposit that is never finalized (relayer downtime, user abandonment, etc.) is vulnerable. The 14-day timelock is a delay, not a prevention.

The sole mitigation is the DAO's ability to call `reject_refund` — an operational control that requires active monitoring of every refund request within the timelock window. [1](#0-0) 

### Recommendation
Remove the conditional: always require the caller to supply a `refund_address` that matches `deposit_msg.refund_address`, and require `deposit_msg.refund_address` to be `Some`. If the protocol must support deposits without a pre-authorized refund address, restrict `request_refund` to the original depositor (verified via `deposit_msg.recipient_id` matching `env::predecessor_account_id()`) or to DAO/Operator roles when `deposit_msg.refund_address` is `None`.

### Proof of Concept
1. Alice calls `get_user_deposit_address(deposit_msg={recipient_id:"alice.near", refund_address:None})` → bridge emits `LogDepositAddress` event with the full `deposit_msg`.
2. Alice sends BTC to the returned deposit address; `verify_deposit` is never called.
3. Attacker observes the NEAR event and the Bitcoin transaction.
4. Attacker calls:
   ```
   request_refund(
     deposit_msg={recipient_id:"alice.near", refund_address:None},
     refund_address="attacker_btc_addr",
     tx_bytes=<alice's tx>,
     vout=0,
     proof=<valid light-client proof>,
     gas_fee=None
   )
   ```
5. Line 154 check is skipped (`deposit_msg.refund_address` is `None`); line 517-525 check passes (same `deposit_msg` → same derived address).
6. `RefundRequest { refund_address: "attacker_btc_addr", ... }` is stored.
7. After `unsafe_refund_timelock_sec`, `execute_refund` is called; MPC signs a BTC transaction to `attacker_btc_addr`.
8. Attacker receives Alice's BTC. [1](#0-0) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-518)
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
```
