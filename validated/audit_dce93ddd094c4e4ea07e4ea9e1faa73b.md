### Title
`request_refund` Proof Is Not Bound to Caller — Refund Address Can Be Front-Run to Redirect User BTC - (File: contracts/satoshi-bridge/src/api/bridge.rs)

---

### Summary

`request_refund()` accepts a BTC transaction inclusion proof and a caller-supplied `refund_address`. When `deposit_msg.refund_address` is `None`, the `refund_address` parameter is stored verbatim and is never validated against the caller's identity. Because the BTC inclusion proof does not commit to the `refund_address`, an attacker who observes a pending `request_refund` call can replay the identical proof with their own BTC address, causing the bridge to store the attacker's address and ultimately send the victim's BTC to the attacker.

---

### Finding Description

`request_refund` is a public, permissionless function (no `#[access_control_any]` guard) that stores a `RefundRequest` keyed by `utxo_storage_key = {tx_id}@{vout}`. [1](#0-0) 

The only binding between the proof and the `refund_address` is a conditional check that fires only when `deposit_msg.refund_address` is already set: [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case for users who did not pre-commit a BTC refund address), the `refund_address` argument is accepted without any binding to the caller. The BTC inclusion proof verifies only that the transaction output matches the deposit address derived from `deposit_msg`: [3](#0-2) 

`get_deposit_path` hashes only the `deposit_msg` fields (`recipient_id`, `post_actions`, `extra_msg`, `safe_deposit`, `refund_address`-from-msg), not the caller-supplied `refund_address` argument: [4](#0-3) 

Therefore the proof is entirely independent of the `refund_address` argument. An attacker can copy every proof field from the victim's pending transaction and substitute their own BTC address.

Once a `RefundRequest` is stored, a duplicate is rejected: [5](#0-4) 

So whichever call lands first wins. After the timelock, `execute_refund` (callable by anyone) sends the BTC to whichever `refund_address` was stored: [6](#0-5) 

---

### Impact Explanation

The attacker permanently redirects the victim's BTC refund to their own BTC address. The victim's `request_refund` call reverts with "Refund request already exists for this UTXO", and the victim has no recourse: the UTXO is now locked to the attacker's refund request. After the timelock, `execute_refund` sends the BTC to the attacker. This is a direct, complete theft of user BTC funds — **Critical**.

---

### Likelihood Explanation

NEAR transactions are visible in the RPC mempool before block finalization (~1 s block time). An attacker running a monitoring bot can observe any `request_refund` call, extract `deposit_msg`, `tx_bytes`, `vout`, and `proof`, substitute their own `refund_address`, and submit the competing transaction in the same or next block. No privileged access, leaked key, or operator cooperation is required. The attack is fully permissionless and mechanically straightforward.

---

### Recommendation

Bind the `refund_address` to the caller's identity so the proof cannot be replayed with a different destination. Two concrete options:

1. **Require `deposit_msg.refund_address` to always be set.** Remove the caller-supplied `refund_address` parameter entirely; the only accepted refund destination is the one committed inside `deposit_msg` (and therefore inside the deposit address derivation). This mirrors the keep-core fix of binding the proof to `msg.sender`.

2. **Two-step commit/reveal.** In step 1 the caller commits `hash(deposit_msg || refund_address || caller_account_id)` with a NEAR deposit. In step 2 (separate block) the caller reveals the preimage. The contract verifies the hash matches the earlier commitment before storing the `RefundRequest`. This prevents front-running because the commitment is already on-chain before the proof is revealed.

---

### Proof of Concept

1. Alice sends 0.1 BTC to the bridge deposit address derived from her `deposit_msg` (`refund_address: None`). The deposit is never finalized.
2. Alice calls `request_refund(deposit_msg, "bc1q...alice...", tx_bytes, vout, proof, None)`.
3. The NEAR transaction is visible in the RPC before inclusion.
4. Attacker Bob copies `deposit_msg`, `tx_bytes`, `vout`, `proof` from Alice's pending call and submits `request_refund(deposit_msg, "bc1q...bob...", tx_bytes, vout, proof, None)` with a higher-priority submission (or simply in the same block before Alice's).
5. Bob's `request_refund_callback` passes all checks — the proof is valid, the output script matches the deposit address, and no prior request exists.
6. `RefundRequest { refund_address: "bc1q...bob..." }` is stored under `{tx_id}@{vout}`.
7. Alice's callback reverts: "Refund request already exists for this UTXO".
8. After `config.unsafe_refund_timelock_sec`, anyone calls `execute_refund("{tx_id}@{vout}", None)`.
9. The bridge builds a BTC transaction paying 0.1 BTC (minus gas fee) to Bob's address and signs it via MPC.
10. Alice's 0.1 BTC is permanently transferred to Bob. [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-345)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

        let deposit_msg = refund_request.deposit_msg();
        let path = get_deposit_path(&deposit_msg);
        let vutxo = VUTXO::Current(UTXO {
            path,
            tx_bytes: refund_request.tx_bytes.0.clone(),
            vout: refund_request.vout,
            balance: u64::try_from(refund_request.amount)
                .unwrap_or_else(|_| env::panic_str("Amount overflow")),
        });

        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```
