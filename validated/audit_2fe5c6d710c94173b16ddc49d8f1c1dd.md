### Title
Permissionless `request_refund` Allows Front-Running to Block Victim's Refund and Redirect BTC - (File: contracts/satoshi-bridge/src/api/bridge.rs)

---

### Summary

Any unprivileged NEAR account can call `request_refund` for a victim's UTXO when `deposit_msg.refund_address = None`, supplying an attacker-controlled BTC address. Because `request_refund_callback` enforces uniqueness per UTXO, the victim's subsequent legitimate refund call is permanently blocked until a DAO/Operator rejects the malicious request. This is a direct analog to M-12: permissionless external state creation that blocks a critical protocol function and requires privileged operator intervention to recover.

---

### Finding Description

`request_refund` in `bridge.rs` carries no caller-identity restriction. Any NEAR account that pays the storage deposit can submit a refund request for any UTXO: [1](#0-0) 

The only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the user did not pre-authorize a BTC return address), the guard is skipped entirely and the caller may supply any `refund_address`.

In `request_refund_callback`, uniqueness is enforced:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

Once an attacker's request is stored, the victim's own `request_refund` call will always revert with this message. The victim's BTC remains locked in the deposit address until a DAO/Operator calls `reject_refund`.

The victim's `deposit_msg` is fully public: `get_user_deposit_address` emits it as a NEAR event: [4](#0-3) 

The BTC transaction bytes and Merkle proof are public on the Bitcoin blockchain. The attacker therefore has all inputs needed to front-run.

After the `unsafe_refund_timelock_sec` elapses (the longer timelock applied to non-pre-authorized addresses), `execute_refund` is also callable by anyone with no role restriction: [5](#0-4) 

The refund is sent to `refund_request.refund_address`, which the attacker set: [6](#0-5) 

---

### Impact Explanation

**Medium — attacker-triggered temporary locking of bridged funds requiring operator intervention.**

The victim's BTC is locked in the deposit address and cannot be refunded until a DAO/Operator calls `reject_refund` to clear the malicious request. The attacker can repeat the front-run immediately after each rejection, keeping the victim's funds stuck indefinitely. Each repetition costs the attacker only the storage deposit. This matches the allowed Medium impact: "attacker-triggered temporary locking of bridged funds."

The scenario where the DAO fails to reject within `unsafe_refund_timelock_sec` (leading to BTC theft) is bounded by the trusted-role oversight assumption and is therefore classified as Medium rather than Critical.

---

### Likelihood Explanation

**Medium.** The attacker needs:
1. The victim's `deposit_msg` — publicly emitted by `get_user_deposit_address` as a NEAR event.
2. The victim's BTC transaction bytes and Merkle proof — publicly available on the Bitcoin blockchain.
3. A NEAR storage deposit — a small, finite cost.

No privileged access, leaked keys, or off-chain coordination is required. The attack is viable for any deposit where the user did not pre-authorize a `refund_address` in their `deposit_msg`.

---

### Recommendation

1. **Require caller to be `deposit_msg.recipient_id`** when `deposit_msg.refund_address` is `None`. This ensures only the intended recipient can initiate a refund with an arbitrary BTC address.
2. **Alternatively, require `deposit_msg.refund_address` to always be `Some`** — i.e., force users to pre-authorize a BTC return address at deposit time. This eliminates the open-refund-address path entirely.
3. If open refund addresses must be supported, **emit a NEAR event immediately when a refund request is created** (already done via `RefundRequested`) and ensure the DAO monitoring pipeline alerts on requests where the caller is not the `recipient_id`.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address(deposit_msg)` where `deposit_msg.refund_address = None`. The `deposit_msg` is emitted as a NEAR event.
2. Alice sends BTC to the returned deposit address. The transaction is confirmed on Bitcoin.
3. The deposit is never finalized (no `verify_deposit` called), so Alice intends to call `request_refund`.
4. Attacker observes Alice's `deposit_msg` from NEAR events and the BTC transaction from the Bitcoin blockchain.
5. Attacker calls `request_refund(alice_deposit_msg, attacker_btc_address, tx_bytes, vout, proof, None)` before Alice, paying the required storage deposit.
6. `request_refund_callback` stores a `RefundRequest` with `refund_address = attacker_btc_address`.
7. Alice calls `request_refund(alice_deposit_msg, alice_btc_address, tx_bytes, vout, proof, None)`. The callback panics: `"Refund request already exists for this UTXO"`. Alice's BTC is now locked.
8. After `unsafe_refund_timelock_sec` elapses (if DAO does not reject), attacker calls `execute_refund(utxo_storage_key, None)`. The bridge constructs a refund PSBT paying `attacker_btc_address` and initiates MPC signing.
9. Alice's BTC is returned to the attacker's address.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-401)
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
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };

        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());

        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```
