### Title
Unauthenticated `request_refund` Allows Attacker to Redirect Victim's BTC to Attacker-Controlled Address When `deposit_msg.refund_address` Is `None` - (File: contracts/satoshi-bridge/src/api/bridge.rs, contracts/satoshi-bridge/src/refund.rs)

---

### Summary

`request_refund` is a fully permissionless function — any NEAR account can call it for any on-chain BTC deposit. When the original `DepositMsg` was constructed with `refund_address: None`, the caller of `request_refund` freely supplies the `refund_address` parameter with no ownership check. An attacker who observes a victim's deposit (whose `deposit_msg` is public via NEAR events) can front-run or race the victim, register a refund request pointing to the attacker's own BTC address, and — after the `unsafe_refund_timelock_sec` elapses — trigger `execute_refund` to permanently redirect the victim's BTC to the attacker.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` accepts a `deposit_msg` and a separate `refund_address` from any caller with no check that `env::predecessor_account_id() == deposit_msg.recipient_id`:

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
    if gas_fee.is_some() { /* only DAO/Operator check */ }
    self.internal_request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, ...)
}
``` [1](#0-0) 

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the `if let` arm is skipped entirely), the caller-supplied `refund_address` is stored verbatim into the `RefundRequest` with no further validation:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-controlled
    ...
};
self.data_mut().refund_requests.insert(utxo_storage_key, refund_request.into());
``` [3](#0-2) 

The `deposit_msg` used to derive the deposit address is emitted as a NEAR event by `get_user_deposit_address`, making it fully public: [4](#0-3) 

Once a refund request exists for a UTXO, a second `request_refund` for the same UTXO is rejected:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [5](#0-4) 

This means once the attacker's request lands, the victim cannot overwrite it with a legitimate one.

After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is also permissionless — any account can trigger it: [6](#0-5) 

The longer `unsafe_refund_timelock_sec` (applied when `deposit_msg.refund_address` is `None`) is the only mitigation, giving DAO/Operator a window to reject the request: [7](#0-6) 

This is a governance-dependent, not cryptographic, safeguard.

---

### Impact Explanation

**Critical.** When a victim deposits BTC using a `DepositMsg` with `refund_address: None` and the deposit is not yet finalized via `verify_deposit`, an attacker can register a refund request pointing to the attacker's own BTC address. After the `unsafe_refund_timelock_sec` passes, `execute_refund` constructs and MPC-signs a Bitcoin transaction sending the victim's full deposit (minus gas fee) to the attacker's address. The victim's BTC is permanently and irrecoverably transferred to the attacker. This constitutes direct theft of user funds locked in the bridge.

---

### Likelihood Explanation

**High.** The `deposit_msg` is emitted as a public NEAR event every time a user calls `get_user_deposit_address`. The BTC deposit transaction is visible on-chain. The attacker needs only: (1) observe the NEAR event to learn the `deposit_msg`, (2) observe the BTC transaction to obtain `tx_bytes` and `vout`, (3) call `request_refund` with their own BTC address before the victim or relayer does. No special privileges, leaked keys, or majority attacks are required. The attack is executable by any unprivileged NEAR account.

---

### Recommendation

Add an ownership check in `request_refund` (or `internal_request_refund`) that enforces the caller is the intended recipient when `deposit_msg.refund_address` is `None`:

```rust
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.recipient_id,
        "Only the deposit recipient can set refund_address when not pre-authorized"
    );
}
```

Alternatively, require that `deposit_msg.refund_address` is always `Some` (i.e., the refund address must be committed at deposit time), eliminating the caller-supplied path entirely.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`. The bridge emits a `LogDepositAddress` event containing the full `deposit_msg`.
2. Alice sends 1 BTC to the returned deposit address. The transaction is confirmed on Bitcoin but `verify_deposit` has not yet been called by the relayer.
3. Attacker observes the NEAR event (learning `deposit_msg`) and the Bitcoin transaction (learning `tx_bytes`, `vout`).
4. Attacker calls:
   ```
   request_refund(
       deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
       refund_address = "attacker_btc_address",
       tx_bytes = <alice's tx>,
       vout = 0,
       proof = <valid merkle proof>,
   )
   ```
5. `internal_request_refund` skips the `refund_address` check (because `deposit_msg.refund_address` is `None`) and stores `RefundRequest { refund_address: "attacker_btc_address", ... }`.
6. Alice attempts `request_refund` with her own address — it fails: `"Refund request already exists for this UTXO"`.
7. After `unsafe_refund_timelock_sec` elapses (assuming DAO does not intervene), attacker calls `execute_refund(utxo_storage_key)`.
8. The bridge constructs a Bitcoin transaction sending Alice's 1 BTC (minus gas fee) to `attacker_btc_address` and requests an MPC signature. Alice's BTC is permanently lost.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
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
