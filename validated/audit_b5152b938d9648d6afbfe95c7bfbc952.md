### Title
Missing BTC Address Validation in `request_refund_callback` Causes Permanently Stuck Refund Requiring Operator Intervention — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

`request_refund_callback` stores a `RefundRequest` with an arbitrary `refund_address` string without validating it as a parseable BTC address. When `execute_refund` is later called, `build_refund_output` calls `Address::parse(...).expect("Invalid refund address")`, which panics and reverts the transaction. The refund request is permanently stuck until DAO/Operator calls `reject_refund`, and the ~2 NEAR storage deposit is permanently lost.

---

### Finding Description

**Entry point — `request_refund` is publicly callable:**

`request_refund` sits in a `#[trusted_relayer] #[near] impl Contract` block but does **not** carry `#[trusted_relayer]` at the method level. The impl-level attribute does not gate all methods — other methods in the same block (`withdraw_rbf`, `claim_lost_found`, `get_user_deposit_address`) are demonstrably public. `request_refund` itself only has `#[payable]` and `#[pause]`. [1](#0-0) 

**Guard in `internal_request_refund` — equality check only, no format validation:**

The only check on `refund_address` is that it equals `deposit_msg.refund_address` when the latter is `Some`. There is no call to `Address::parse` or any other BTC address format check. [2](#0-1) 

**`request_refund_callback` stores the address verbatim:**

After light-client verification succeeds, the callback stores `RefundRequest{refund_address, ...}` with no address validation. [3](#0-2) 

**`build_refund_output` panics on invalid address:**

When `execute_refund` is eventually called, `build_refund_output` calls `Address::parse(refund_address, ...).expect("Invalid refund address")`. If the stored address is not a valid BTC address, this panics and reverts the transaction. [4](#0-3) 

`internal_execute_refund` calls `build_refund_output` directly with the stored `refund_address`: [5](#0-4) 

**`reject_refund` does not refund the NEAR deposit:**

When DAO/Operator calls `reject_refund` to clean up the stuck request, the ~2 NEAR storage deposit is simply discarded — there is no refund mechanism. [6](#0-5) 

---

### Impact Explanation

- The refund request is permanently stuck in `refund_requests` storage. `execute_refund` will always panic on it.
- The BTC UTXO is temporarily locked — it cannot be claimed via `verify_deposit` (the UTXO is not yet in `verified_deposit_utxo`, but the duplicate-request guard in `request_refund_callback` blocks a second valid refund request for the same UTXO until DAO/Operator rejects the first).
- The ~2 NEAR storage deposit paid by the caller is permanently lost.
- Recovery requires privileged DAO/Operator intervention via `reject_refund`.

This matches the Medium scope: **attacker-triggered temporary locking of bridged funds requiring operator intervention**.

---

### Likelihood Explanation

- `request_refund` is publicly callable by any NEAR account.
- No check prevents a third party from submitting a refund request for someone else's unfinalized deposit.
- The attacker only needs a valid BTC transaction proof for an unfinalized deposit (visible on-chain) and ~2 NEAR.
- The scenario also arises accidentally: a legitimate user who mistypes their BTC refund address loses their 2 NEAR and has their BTC locked until operator intervention.

---

### Recommendation

Validate `refund_address` as a parseable BTC address **before** storing the `RefundRequest` in `request_refund_callback` (or in `internal_request_refund` before the async light-client call):

```rust
// In request_refund_callback, before constructing RefundRequest:
crate::network::Address::parse(&refund_address, config.chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This ensures that any `RefundRequest` stored on-chain is guaranteed to be executable by `build_refund_output`.

---

### Proof of Concept

Call sequence:

1. Attacker calls `request_refund` with `deposit_msg.refund_address = Some("not_a_btc_address")`, `refund_address = "not_a_btc_address"`, and a valid proof for a real unfinalized deposit UTXO.
2. `internal_request_refund`: equality check passes (`"not_a_btc_address" == "not_a_btc_address"`). No address format check. Light-client verification is dispatched.
3. `request_refund_callback`: light-client returns `true`. `RefundRequest{refund_address: "not_a_btc_address", ...}` is inserted into `refund_requests`.
4. Timelock elapses. Anyone calls `execute_refund(utxo_storage_key, None)`.
5. `internal_execute_refund` → `build_refund_output("not_a_btc_address", ...)` → `Address::parse("not_a_btc_address", chain).expect("Invalid refund address")` → **panic / transaction revert**.
6. The `RefundRequest` remains in storage. `execute_refund` will panic on every subsequent call. DAO/Operator must call `reject_refund` to unblock the UTXO. The 2 NEAR deposit is gone.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-297)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
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
