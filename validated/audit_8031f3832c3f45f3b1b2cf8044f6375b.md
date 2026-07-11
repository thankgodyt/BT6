Now I have all the information needed. Let me trace the complete attack path.

**Key findings:**

1. `get_deposit_path` hashes the entire `deposit_msg` JSON including `refund_address` — so a `deposit_msg` with `refund_address: None` produces a distinct deposit address from one with `refund_address: Some(...)`. [1](#0-0) 

2. `request_refund` and `execute_refund` are in the `#[trusted_relayer] #[near] impl Contract` block at line 480, but neither method carries an individual `#[trusted_relayer]` attribute. Only `verify_refund_finalize` and `remove_refund_pending_tx_id` carry the per-method attribute. The doc comment confirms: "After the timelock period, **anyone** can call `execute_refund`." [2](#0-1) 

3. When `deposit_msg.refund_address` is `None`, `internal_request_refund` skips the address-match check entirely and stores the caller-supplied `refund_address` verbatim. [3](#0-2) 

4. `resolve_execute_refund_timelock` returns `config.unsafe_refund_timelock_sec` for the `None` case — a longer timelock intended to give DAO/Operator time to reject, but no cryptographic enforcement. [4](#0-3) 

5. `internal_execute_refund` (Bitcoin path) builds the PSBT output directly from `refund_request.refund_address` — the attacker-supplied address — with no further authorization check. [5](#0-4) 

6. The `request_refund_callback` only verifies that the tx output script matches the deposit address derived from `deposit_msg`. Since the attacker uses the victim's exact `deposit_msg` (with `refund_address: None`), this check passes. [6](#0-5) 

---

### Title
Unprivileged caller can redirect any `refund_address: None` deposit refund to an attacker-controlled BTC address — (`contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`request_refund` is callable by any NEAR account. When the original deposit was made with `deposit_msg.refund_address = None`, an attacker can call `request_refund` with the victim's `deposit_msg` and supply their own BTC address as `refund_address`. After `unsafe_refund_timelock_sec` elapses, the attacker calls `execute_refund` and the bridge MPC-signs a PSBT paying the victim's BTC to the attacker's address.

### Finding Description
`request_refund` has no per-method `#[trusted_relayer]` guard and no check that the caller is the `deposit_msg.recipient_id` or the original depositor. [7](#0-6) 

When `deposit_msg.refund_address` is `None`, the only validation in `internal_request_refund` is that the BTC tx is included in the chain and that the output script matches the deposit address derived from `deposit_msg`. An attacker who observes the victim's deposit on-chain can reconstruct the exact `deposit_msg` (it is emitted in `LogDepositAddress` events) and call `request_refund` with `refund_address = attacker_btc_address`. The callback stores this address in `RefundRequest.refund_address`. [8](#0-7) 

`execute_refund` is also ungated (no per-method `#[trusted_relayer]`). After `unsafe_refund_timelock_sec`, the attacker calls it; `internal_execute_refund` builds the PSBT output from `refund_request.refund_address` (the attacker's address) without any further authorization. [9](#0-8) 

The sole defense is the DAO/Operator calling `reject_refund` within the timelock window — a liveness-dependent operational control, not a cryptographic invariant.

### Impact Explanation
Any deposit made with `deposit_msg.refund_address = None` (the common case for standard deposits) that has not yet been finalized via `verify_deposit` is vulnerable. An attacker can steal the depositor's BTC by redirecting the refund PSBT to an attacker-controlled address. This is a direct, critical loss of user funds.

### Likelihood Explanation
- `deposit_msg.refund_address: None` is the default for standard deposits (confirmed by test fixtures and the `DepositMsg` struct's `skip_serializing_if = "Option::is_none"` default).
- The attack requires only: knowledge of the victim's deposit tx (public on Bitcoin), the `deposit_msg` (emitted in `LogDepositAddress` events on NEAR), and waiting for `unsafe_refund_timelock_sec`.
- The DAO/Operator must actively monitor every refund request and reject suspicious ones within the timelock. Any liveness gap (downtime, high volume, missed event) enables the theft.

### Recommendation
Add a caller-authorization check in `request_refund`: when `deposit_msg.refund_address` is `None`, require that `env::predecessor_account_id() == deposit_msg.recipient_id`, or require the caller to prove ownership of the deposit (e.g., via a signed message). Alternatively, when `refund_address` is caller-supplied, store the requesting account and require the same account to call `execute_refund`.

### Proof of Concept
```
1. Alice deposits BTC using deposit_msg = { recipient_id: "alice.near", refund_address: None }
   → deposit address = hash(deposit_msg_json)
   → tx confirmed on Bitcoin, verify_deposit never called

2. Attacker observes the deposit tx on Bitcoin and the LogDepositAddress event on NEAR.

3. Attacker calls request_refund(
       deposit_msg = { recipient_id: "alice.near", refund_address: None },  // same as Alice's
       refund_address = "attacker_btc_address",
       tx_bytes = <Alice's deposit tx>,
       vout = 0,
       proof = <valid inclusion proof>
   )
   → internal_request_refund: deposit_msg.refund_address is None → skip address-match check
   → request_refund_callback: script_pubkey matches (same deposit_msg) → stores RefundRequest
     with refund_address = "attacker_btc_address"

4. Wait unsafe_refund_timelock_sec (DAO/Operator does not reject).

5. Attacker calls execute_refund(utxo_storage_key)
   → resolve_execute_refund_timelock returns unsafe_refund_timelock_sec (elapsed)
   → internal_execute_refund builds PSBT: output pays "attacker_btc_address"
   → MPC signs the PSBT

6. Attacker broadcasts the signed tx → Alice's BTC arrives at attacker_btc_address.
```

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-589)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    // ── Refund API ──

    /// Submit a refund request for a deposit that was never finalized via `verify_deposit` or `safe_verify_deposit`.
    /// The BTC transaction is verified through the Light Client to prove the deposit exists.
    /// After the timelock period, anyone can call `execute_refund` to initiate the return.
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
    /// # Arguments
    ///
    /// * `deposit_msg` - The original deposit message. If `deposit_msg.refund_address` is set,
    ///   it must match the provided `refund_address`.
    /// * `refund_address` - BTC address to send the refund to. If `deposit_msg.refund_address`
    ///   is `None`, this value is used directly.
    /// * `tx_bytes` - BTC transaction bytes proving the deposit.
    /// * `vout` - Output index of the deposit in the transaction.
    /// * `proof` - Transaction inclusion proof for Light Client verification, bundling:
    ///   `tx_block_blockhash` (block hash containing the transaction), `tx_index`
    ///   (transaction index within the block), `merkle_proof` (Merkle proof of the
    ///   transaction), and the coinbase fields `coinbase_tx_id` and
    ///   `coinbase_merkle_proof` used to verify the block's coinbase.
    /// * `gas_fee` - Optional custom gas fee. Only DAO or Operator can set this.
    ///   If `None`, the default `config.max_btc_gas_fee` is used during `execute_refund`.
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

    /// Reject a pending refund request.
    /// - DAO or Operator can reject any request.
    /// - Anyone can reject a request if the UTXO has already been verified via `verify_deposit`
    ///
    /// # Arguments
    ///
    /// * `utxo_storage_key` - The UTXO key identifying the refund request (`{tx_id}@{vout}`).
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
    }

    /// Execute a refund: send the deposit UTXO back to the original
    /// `refund_address` via the MPC sign pipeline. Requires the timelock to have
    /// passed (bypassed for a privileged caller with a pre-authorized address).
    ///
    /// # Arguments
    ///
    /// * `utxo_storage_key` - Refund request key (`{tx_id}@{vout}`).
    /// * `chain_specific_data` - Zcash only: `Some` with an Orchard bundle for a
    ///   shielded refund, `None` for transparent. Ignored on Bitcoin.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-228)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L516-525)
```rust
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L24-43)
```rust
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
```
