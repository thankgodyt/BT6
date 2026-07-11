### Title
Unbound `refund_address` in `request_refund` Enables Theft of Unfinalized Deposits — (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `refund_address` parameter accepted by `request_refund` is never bound to the BTC inclusion proof. Any unprivileged NEAR account that learns the original `deposit_msg` and obtains the publicly-available inclusion proof for a deposit whose `deposit_msg.refund_address` is `None` can front-run the legitimate user, register a malicious refund destination, and—after the timelock—drain the deposited BTC to an attacker-controlled address.

---

### Finding Description

The vulnerability class from the external report is: *a parameter that should be cryptographically bound to a proof is instead accepted as a free caller-supplied argument and stored without that binding*. The exact same pattern exists in the bridge's refund subsystem.

**Deposit address derivation binds `deposit_msg` to the proof, but not `refund_address`.**

`get_deposit_path` hashes the entire `deposit_msg` to derive the on-chain deposit address: [1](#0-0) 

The BTC inclusion proof therefore cryptographically commits to every field inside `deposit_msg`. However, `refund_address` is a *separate* parameter passed alongside `deposit_msg` to `request_refund`: [2](#0-1) 

Inside `request_refund_callback` (the post-proof callback), the contract verifies that the transaction output matches the deposit address derived from `deposit_msg`, but it never checks that `refund_address` was committed to anywhere in the proof: [3](#0-2) 

The only guard is: if `deposit_msg.refund_address` is already set, the caller-supplied `refund_address` must match it: [4](#0-3) 

When `deposit_msg.refund_address` is `None` (the common case—it is an `Option` and `skip_serializing_if = "Option::is_none"`), the caller-supplied `refund_address` is accepted verbatim and stored: [5](#0-4) 

**`request_refund` is callable by any NEAR account.** The `#[trusted_relayer]` attribute appears on the `impl` block as a configuration macro; the individual method carries only `#[payable]` and `#[pause]`, not a per-method `#[trusted_relayer]` guard (compare with `verify_refund_finalize` and `remove_refund_pending_tx_id`, which do carry the per-method attribute): [6](#0-5) 

**`execute_refund` is also callable by any NEAR account** after the timelock elapses: [7](#0-6) 

The only post-submission protection is the `unsafe_refund_timelock_sec` window during which DAO/Operator can call `reject_refund`. Ordinary users cannot reject a refund request: [8](#0-7) 

Once the attacker's request is stored, the legitimate depositor has no on-chain recourse.

---

### Impact Explanation

An attacker who successfully front-runs `request_refund` with a malicious `refund_address` and survives the `unsafe_refund_timelock_sec` window receives the full deposited BTC (minus gas fee) at their own Bitcoin address. The legitimate depositor loses their funds entirely. This is direct, irreversible theft of user funds matching the **Critical** impact tier: *Significant loss or theft of user funds*.

---

### Likelihood Explanation

All inputs the attacker needs are publicly observable:

1. **`deposit_msg`** — passed as a plain argument to `verify_deposit` / `verify_deposit_v2` on NEAR; visible in transaction history. It is also emitted in `LogDepositAddress` events whenever `get_user_deposit_address` is called.
2. **`tx_bytes` and inclusion proof** — the Bitcoin transaction and its Merkle proof are publicly available on the Bitcoin blockchain.
3. **`vout`** — derivable from the transaction output matching the deposit address.

The attacker only needs to monitor NEAR for failed or pending `verify_deposit` calls, extract `deposit_msg`, fetch the Bitcoin proof, and call `request_refund` before the legitimate user does. Because `request_refund` requires an attached NEAR storage deposit (not a large amount), the cost of the attack is low. The only probabilistic mitigation is DAO/Operator vigilance during the `unsafe_refund_timelock_sec` window, which is an operational control, not a cryptographic one.

---

### Recommendation

Mirror the fix applied in the referenced report: bind `refund_address` to the data that is already verified by the proof. Concretely:

1. **Require `deposit_msg.refund_address` to be set** for any refund request submitted by an unprivileged caller. Because `deposit_msg` is hashed into the deposit address (and thus into the inclusion proof), a pre-committed `refund_address` inside `deposit_msg` is automatically proof-bound.
2. Alternatively, **restrict `request_refund` to `deposit_msg.recipient_id`** (the intended NEAR beneficiary), so only the account that was supposed to receive nBTC can initiate a refund.
3. As a defence-in-depth measure, emit a `RefundRequested` event immediately when the request is submitted (before the callback) so monitoring systems can detect and reject suspicious requests faster.

---

### Proof of Concept

```
1. Alice deposits 0.1 BTC to the bridge with:
     deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }
   The deposit address is sha256(json(deposit_msg)) → derived BTC address.

2. verify_deposit_v2 is called by a relayer but fails (e.g., Alice's NEAR
   account has no storage). The deposit_msg is visible in the NEAR tx args.

3. Attacker Bob:
   a. Reads deposit_msg from the failed NEAR transaction.
   b. Fetches tx_bytes and Merkle proof from the Bitcoin blockchain.
   c. Calls:
        request_refund(
          deposit_msg,                  // same as Alice's
          "bob_btc_address",            // attacker-controlled
          tx_bytes,
          vout,
          proof,
          None
        )
      with the required NEAR storage deposit attached.

4. request_refund_callback runs:
   - Verifies inclusion proof: ✓
   - Verifies output.script_pubkey == deposit_address(deposit_msg): ✓
   - deposit_msg.refund_address is None → no address check.
   - Stores RefundRequest { refund_address: "bob_btc_address", ... }.

5. After unsafe_refund_timelock_sec elapses (DAO/Operator did not reject):
   Bob calls execute_refund(utxo_storage_key, None).

6. The bridge builds a PSBT paying 0.1 BTC (minus gas fee) to "bob_btc_address",
   requests an MPC signature, and broadcasts the transaction.
   Alice's 0.1 BTC is sent to Bob.
```

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L516-526)
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
