### Title
Front-Running of `request_refund` Enables Attacker to Redirect BTC Refund to Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary

`request_refund` is publicly callable by any NEAR account and accepts an arbitrary `refund_address` BTC parameter when `deposit_msg.refund_address` is `None`. Because NEAR transactions are visible in the mempool before finalization, an attacker can observe a user's `request_refund` call, front-run it with the same proof arguments but substitute their own BTC address as `refund_address`, causing the user's transaction to fail and the refund request to be registered pointing to the attacker's address.

### Finding Description

`request_refund` performs no check that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`. The only guard on `refund_address` is: [1](#0-0) 

This guard only fires when `deposit_msg.refund_address` is `Some(...)`. When it is `None` (the "unsafe" path), the caller-supplied `refund_address` is accepted verbatim and stored in the `RefundRequest`: [2](#0-1) 

In `request_refund_callback`, a duplicate-request guard prevents a second registration for the same UTXO: [3](#0-2) 

So whichever call lands first wins. The attacker's front-run registers the refund request with the attacker's BTC address; the user's subsequent call reverts.

After `unsafe_refund_timelock_sec` elapses, `execute_refund` is permissionless — anyone can call it: [4](#0-3) 

`finalize_refund_with_psbt` then builds a Bitcoin transaction paying `refund_request.refund_address` (the attacker's address) and submits it to MPC for signing: [5](#0-4) 

### Impact Explanation

The user's BTC deposit is sent to the attacker's Bitcoin address. The user loses their entire deposit. This is a direct, complete theft of user funds. The only on-chain mitigation is the `unsafe_refund_timelock_sec` window during which the DAO/Operator can call `reject_refund`. If the operator is offline, slow, or the timelock is short, the theft completes.

Impact: **Critical — Significant loss/theft of user funds.**

### Likelihood Explanation

- NEAR transactions are publicly visible in the mempool before block inclusion, making the proof arguments trivially copyable.
- `request_refund` is callable by any NEAR account (confirmed by integration tests where `"alice"`, a non-relayer, calls it successfully).
- The attacker only needs to pay the NEAR storage anti-spam deposit (a small fixed cost) to execute the attack.
- The `deposit_msg.refund_address = None` path is the standard path for users who did not pre-authorize a refund address at deposit time.
- The sole mitigation (DAO/Operator rejection within `unsafe_refund_timelock_sec`) is an off-chain operational assumption, not an on-chain invariant.

Likelihood: **Medium** (requires mempool monitoring and a race, but no privileged access).

### Recommendation

Add a caller-authorization check in `request_refund` (or `internal_request_refund`) requiring that `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. Alternatively, adopt the same pattern used for the safe path: require the refund address to be committed in the `deposit_msg` at deposit time (i.e., always require `deposit_msg.refund_address` to be `Some`), eliminating the unsafe path entirely.

### Proof of Concept

1. Alice deposits BTC to the bridge address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`.
2. Alice submits `request_refund(deposit_msg, refund_address="bc1qalice...", tx_bytes, vout, proof)` to the NEAR network.
3. Attacker observes Alice's pending transaction in the NEAR mempool.
4. Attacker submits `request_refund(deposit_msg, refund_address="bc1qattacker...", tx_bytes, vout, proof)` with higher priority (or simply in the same block before Alice's).
5. Attacker's `request_refund_callback` runs first; `refund_requests[utxo_key]` is inserted with `refund_address = "bc1qattacker..."`.
6. Alice's `request_refund_callback` hits the duplicate guard at line 544–547 of `refund.rs` and reverts.
7. After `unsafe_refund_timelock_sec`, attacker (or any account) calls `execute_refund(utxo_key)`.
8. `finalize_refund_with_psbt` builds a Bitcoin transaction paying `"bc1qattacker..."` and requests MPC signature.
9. MPC signs; the signed transaction is broadcast; Alice's BTC arrives at the attacker's address. [6](#0-5) [3](#0-2) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-158)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L323-325)
```rust
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

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
