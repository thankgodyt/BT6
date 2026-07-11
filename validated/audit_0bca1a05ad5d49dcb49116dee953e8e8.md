### Title
Any caller can redirect a BTC refund to an arbitrary address via `request_refund` — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is a public, permissionless function. When the original `deposit_msg.refund_address` field is `None`, the caller is free to supply any BTC address as `refund_address`. Because the `deposit_msg` is publicly broadcast via on-chain events and the deposit transaction is visible on Bitcoin, an attacker can front-run a legitimate user's refund request and register their own BTC address as the destination, causing the user's BTC to be sent to the attacker after the timelock expires.

---

### Finding Description

`request_refund` accepts a caller-supplied `refund_address` parameter with no validation that the caller is the original depositor: [1](#0-0) 

Inside `internal_request_refund`, the only guard on `refund_address` is a conditional equality check that fires only when `deposit_msg.refund_address` is already set: [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case for standard deposits), the supplied `refund_address` is stored verbatim with no further validation: [3](#0-2) 

The `deposit_msg` used to derive the deposit address is publicly emitted in a `LogDepositAddress` event every time `get_user_deposit_address` is called: [4](#0-3) 

A duplicate-request guard means only one refund request can exist per UTXO: [5](#0-4) 

This means a front-running attacker who wins the race permanently blocks the legitimate user's request and installs their own BTC address as the refund destination.

After `unsafe_refund_timelock_sec` elapses, `execute_refund` is also permissionless: [6](#0-5) 

The attacker can then call `execute_refund` themselves, causing `finalize_refund_with_psbt` to build and sign a PSBT that pays the attacker's BTC address: [7](#0-6) 

---

### Impact Explanation

If the DAO does not reject the malicious request within `unsafe_refund_timelock_sec`, the user's deposited BTC is permanently transferred to the attacker's address. This constitutes a complete, irreversible theft of user funds — a Critical impact under the allowed scope ("Significant loss, theft, destruction, or permanent locking of user or protocol funds").

The DAO's `reject_refund` capability is a mitigation that requires active, continuous monitoring; it is not a prevention. The root cause is entirely in the on-chain code.

---

### Likelihood Explanation

All information required to mount the attack is publicly available:

1. `deposit_msg` is broadcast in a NEAR event every time a user calls `get_user_deposit_address`.
2. The corresponding BTC deposit transaction is visible on the Bitcoin blockchain.
3. The Merkle proof needed for `request_refund` can be constructed from public Bitcoin block data.

The attacker only needs to pay the small NEAR storage deposit required by `required_balance_for_request_refund`. No privileged access, leaked key, or malicious operator is required. Any unprivileged NEAR account can execute this attack against any deposit whose `deposit_msg.refund_address` is `None`.

---

### Recommendation

1. **Bind `refund_address` to the depositor identity**: Require `env::predecessor_account_id()` to match the NEAR account embedded in `deposit_msg`, or require `deposit_msg.refund_address` to be non-`None` for permissionless refund requests.
2. **Alternatively, restrict `request_refund` to the depositor**: Only allow the NEAR account named in `deposit_msg` (or a DAO/Operator) to submit a refund request for a given UTXO.
3. **Emit a warning event** when a refund request is submitted by an account that does not match the depositor in `deposit_msg`, to aid DAO monitoring.

---

### Proof of Concept

1. User calls `get_user_deposit_address(deposit_msg)` — NEAR emits `LogDepositAddress { deposit_msg, deposit_address }`.
2. User sends BTC to `deposit_address`; the transaction `tx_bytes` and Merkle proof become public.
3. User prepares a call to `request_refund(deposit_msg, user_btc_addr, tx_bytes, vout, proof, None)`.
4. Attacker observes the NEAR event and the pending NEAR transaction in the mempool.
5. Attacker submits `request_refund(deposit_msg, attacker_btc_addr, tx_bytes, vout, proof, None)` with higher gas, winning the race.
6. The duplicate-request guard (`"Refund request already exists for this UTXO"`) causes the user's subsequent call to revert.
7. The refund request is now stored with `refund_address = attacker_btc_addr`.
8. After `unsafe_refund_timelock_sec` elapses (assuming DAO does not reject), attacker calls `execute_refund(utxo_storage_key, None)`.
9. The bridge builds and MPC-signs a Bitcoin transaction paying `attacker_btc_addr` the full deposit minus gas fee.
10. User's BTC is permanently lost.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-325)
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
