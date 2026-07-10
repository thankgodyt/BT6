### Title
Unvalidated `refund_address` String Stored Without Format Check Causes Permanently Stuck Refund State - (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

`request_refund` accepts a caller-supplied `refund_address: String` and stores it in `RefundRequest` without validating it as a well-formed BTC/ZEC address. Address parsing only occurs later inside `execute_refund` → `build_refund_output`, where an invalid string causes an irrecoverable panic. An unprivileged caller who knows a victim's `deposit_msg` (where `deposit_msg.refund_address` is `None`) can front-run the victim's refund with an invalid address string, permanently blocking the refund path for that UTXO until DAO/Operator intervention.

---

### Finding Description

`internal_request_refund` performs only one address-related check: if `deposit_msg.refund_address` is `Some`, it must equal the provided `refund_address`. When `deposit_msg.refund_address` is `None`, the caller-supplied string is accepted and forwarded to `request_refund_callback` with no format validation: [1](#0-0) 

`request_refund_callback` stores the raw string directly into `RefundRequest`: [2](#0-1) 

Address parsing is deferred to `build_refund_output`, called only at `execute_refund` time: [3](#0-2) 

If `refund_address` is not a valid BTC/ZEC address, `Address::parse` returns `Err`, and `.expect("Invalid refund address")` panics — permanently blocking `execute_refund` for that request. The `RefundRequest` remains in storage with `executed: false`, and the deposit UTXO is never added to `verified_deposit_utxo` (that only happens inside `finalize_refund_with_psbt`, which is never reached). [4](#0-3) 

---

### Impact Explanation

- The stuck `RefundRequest` blocks any further `request_refund` for the same UTXO (duplicate check at callback line 544–547).
- `execute_refund` will always panic for this request; the refund path is permanently closed until DAO/Operator calls `reject_refund`.
- The victim can still call `verify_deposit` to mint nBTC (deposit verification does not check for existing refund requests), but is forced off the intended refund path.
- After `verify_deposit` succeeds, `reject_refund` becomes permissionless — but this requires the victim to abandon the refund and accept nBTC instead.

This maps to **Medium** impact: attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention. [5](#0-4) 

---

### Likelihood Explanation

- `request_refund` is callable by any account that attaches the required storage deposit (the anti-spam fee). Test evidence shows regular user accounts (`alice`, `bob`) calling it and receiving business-logic errors rather than access-control rejections, confirming it is not restricted to privileged roles.
- The attacker only needs to observe a pending deposit on-chain (the `deposit_msg` is public), reconstruct it, and call `request_refund` before the victim calls `verify_deposit`, supplying any non-address string (e.g., `"invalid"`, `""`, `"garbage"`).
- The attack is cheap: it costs only the required storage deposit (a small NEAR amount). [6](#0-5) 

---

### Recommendation

Validate `refund_address` as a well-formed address for the configured chain at the entry point of `internal_request_refund`, before the Light Client cross-contract call is dispatched. Specifically, call `crate::network::Address::parse(&refund_address, config.chain.clone())` and `require!` it succeeds. This mirrors the validation already performed in `build_refund_output` but moves it to the earliest possible point, preventing invalid addresses from ever entering contract storage. [7](#0-6) 

---

### Proof of Concept

1. Alice sends BTC to her bridge deposit address, derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`.
2. Attacker observes the transaction on-chain, reconstructs `deposit_msg`, and calls:
   ```
   request_refund(
     deposit_msg,
     refund_address = "not_a_valid_btc_address",
     tx_bytes = <Alice's tx>,
     vout = 0,
     proof = <valid Light Client proof>,
     gas_fee = None,
   )
   ```
   with the required storage deposit attached.
3. Light Client verifies the transaction; `request_refund_callback` stores `RefundRequest { refund_address: "not_a_valid_btc_address", ... }`.
4. Alice (or anyone) calls `execute_refund(utxo_storage_key)`. `build_refund_output` calls `Address::parse("not_a_valid_btc_address", chain)`, which returns `Err`, and `.expect("Invalid refund address")` panics. The call fails.
5. Alice cannot create a new refund request (duplicate check: "Refund request already exists for this UTXO"). She must either call `verify_deposit` to receive nBTC instead, or wait for DAO/Operator to call `reject_refund`. [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-159)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L293-308)
```rust
    /// Build a transparent refund output paying `refund_amount` to `refund_address`.
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
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

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
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
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L18-44)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        _chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
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
