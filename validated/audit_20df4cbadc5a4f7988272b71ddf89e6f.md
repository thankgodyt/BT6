### Title
Unvalidated `refund_address` in `request_refund_callback` causes `execute_refund` to panic and permanently locks deposit UTXO — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

`request_refund_callback` stores the caller-supplied `refund_address` string verbatim without any format validation. When `execute_refund` is later called, `build_refund_output` calls `Address::parse(...).expect("Invalid refund address")`, which panics on any malformed string. The deposit UTXO is then permanently stuck in `refund_requests` and cannot be refunded without DAO/Operator calling `reject_refund`.

---

### Finding Description

The question's framing contains one inaccuracy worth clarifying: the `script_pubkey` equality check in `request_refund_callback` validates the **deposit output** against the deposit address derived from `deposit_msg` — it does not validate `refund_address` at all. The `refund_address` is stored entirely unchecked.

**`request_refund_callback` — no validation of `refund_address`:** [1](#0-0) 

The check at lines 522–525 compares `deposit_script_pubkey == output.script_pubkey` — this is about the deposit output, not the refund address. After this check, `refund_address` is stored as-is: [2](#0-1) 

**`build_refund_output` — panics on invalid address:** [3](#0-2) 

`Address::parse` returns `Err(String)` for any unrecognized format, and `.expect(...)` converts that into a NEAR panic, aborting the entire `execute_refund` call.

**`internal_execute_refund` (Bitcoin path) — the panic site:** [4](#0-3) 

The panic at line 30 leaves `refund_requests` unmodified — the entry is never removed, and the UTXO is never freed.

**`request_refund` is publicly callable** (no `#[trusted_relayer]` on the function itself, unlike `verify_deposit`, `verify_withdraw`, etc.): [5](#0-4) 

**`execute_refund` is also publicly callable:** [6](#0-5) 

---

### Impact Explanation

Once the malformed `refund_address` is stored, every call to `execute_refund` for that UTXO will panic at `build_refund_output`. The deposit UTXO remains in `refund_requests` indefinitely. The only recovery path is for DAO/Operator to call `reject_refund`: [7](#0-6) 

After rejection, the user must re-submit `request_refund` with a valid address and wait out the full timelock again. This matches the **Medium** scoped impact: attacker-triggered temporary locking of bridged funds requiring operator intervention.

---

### Likelihood Explanation

- `request_refund` is publicly callable by any NEAR account with sufficient attached deposit.
- The attacker only needs a real, unfinalized deposit UTXO (provable via the light client) — they do not need to own it.
- Submitting `refund_address = "INVALID"` requires no special knowledge or privilege.
- The `unsafe_refund_timelock_sec` (longer timelock for caller-supplied addresses) gives DAO time to reject, but only if they are monitoring; the vulnerability is still reachable.

---

### Recommendation

Validate `refund_address` in `request_refund_callback` (or in `internal_request_refund` before the async light-client call) by calling `Address::parse` and returning an error instead of storing an unparseable string:

```rust
// In request_refund_callback, before storing:
crate::network::Address::parse(&refund_address, config.chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This converts the deferred panic into an early, clean rejection at request time, before any state is written.

---

### Proof of Concept

Call sequence (Bitcoin, no `zcash` feature):

1. Attacker calls `request_refund` with a valid deposit UTXO (light-client proof passes) and `refund_address = "not_a_btc_address"`.
2. `request_refund_callback` stores `RefundRequest { refund_address: "not_a_btc_address", ... }` — no validation.
3. `unsafe_refund_timelock_sec` elapses.
4. Anyone calls `execute_refund(utxo_storage_key, None)`.
5. `internal_execute_refund` → `build_refund_output("not_a_btc_address", ...)` → `Address::parse` returns `Err(...)` → `.expect("Invalid refund address")` panics.
6. NEAR reverts the call; `refund_requests` still contains the entry.
7. Every subsequent `execute_refund` call panics identically.
8. DAO/Operator must call `reject_refund` to unblock the UTXO.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L294-298)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L24-31)
```rust
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

```

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
