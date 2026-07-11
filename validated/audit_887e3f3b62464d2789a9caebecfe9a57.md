### Title
Attacker-Controlled `refund_address` in Publicly Callable `request_refund` Enables Theft of Unfinalized User Deposits — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is callable by any unprivileged NEAR account. When a deposit's `deposit_msg.refund_address` is `None` (the standard case), an attacker can submit a refund request for a victim's unfinalized deposit while supplying their own Bitcoin address as `refund_address`. After the `unsafe_refund_timelock_sec` elapses, the attacker calls `execute_refund` to redirect the victim's BTC to themselves.

---

### Finding Description

The `request_refund` function carries `#[payable]` and `#[pause(except(roles(Role::DAO)))]` but **no** `#[trusted_relayer]` guard on the function itself: [1](#0-0) 

The impl block is annotated `#[trusted_relayer]`, but the codebase's own pattern proves that annotation is **not** a blanket guard on every function in the block. Functions that are actually relayer-restricted carry the attribute on the function too — compare `verify_refund_finalize` and `remove_refund_pending_tx_id`: [2](#0-1) 

`request_refund`, `reject_refund`, and `execute_refund` deliberately omit the per-function attribute, making them open to any NEAR account.

Inside `request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [3](#0-2) 

When `deposit_msg.refund_address` is `None` — the common path for standard deposits — **no ownership check is performed**. The caller-supplied `refund_address` is stored verbatim: [4](#0-3) 

The `deposit_msg` (including `recipient_id`) is publicly emitted on-chain by `get_user_deposit_address`: [5](#0-4) 

Bitcoin transaction bytes and Merkle proofs are also public. An attacker therefore has all inputs needed to call `request_refund` for any victim deposit.

The `unsafe_refund_timelock_sec` is the only mitigation — it gives the DAO/Operator a window to call `reject_refund`. But `execute_refund` is also callable by any NEAR account: [6](#0-5) 

If the operator window is missed, `execute_refund` builds a signed PSBT paying the attacker's Bitcoin address and submits it to the MPC for signing.

---

### Impact Explanation

**Critical.** If the DAO/Operator fails to reject the request within `unsafe_refund_timelock_sec`, the victim's BTC is permanently redirected to the attacker's Bitcoin address via the MPC signing pipeline. This constitutes significant, irreversible loss of user funds — matching the "significant loss, theft, destruction, or permanent locking of user or protocol funds" criterion.

---

### Likelihood Explanation

**Medium.** All required inputs (deposit_msg from NEAR events, tx_bytes and Merkle proof from Bitcoin) are publicly observable. The attack requires no special privileges, only a NEAR account and the attached storage deposit. The attacker can time the `request_refund` call to coincide with periods of low operator activity (weekends, incidents) to maximize the chance the rejection window is missed.

---

### Recommendation

Add `#[trusted_relayer]` to `request_refund` itself (consistent with `verify_refund_finalize`), restricting submission to whitelisted relayers. Alternatively, require the caller to be the `recipient_id` encoded in `deposit_msg`, or require `deposit_msg.refund_address` to be pre-set (non-`None`) before a permissionless refund path is allowed.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with her `deposit_msg` (`recipient_id = alice.near`, `refund_address = None`). The event is emitted on-chain.
2. Alice sends 0.1 BTC to the derived deposit address. The transaction is confirmed on Bitcoin.
3. Attacker observes Alice's `deposit_msg` from NEAR events and the Bitcoin transaction from the mempool/block explorer.
4. Before Alice's relayer calls `verify_deposit`, the attacker calls:
   ```
   request_refund(
     deposit_msg = alice_deposit_msg,   // observed from NEAR events
     refund_address = "attacker_btc_address",
     tx_bytes = alice_tx_bytes,         // from Bitcoin
     vout = 0,
     proof = alice_merkle_proof,        // from Bitcoin light client
     gas_fee = None
   )
   ```
   with the required NEAR storage deposit attached.
5. The light client verifies the transaction. The refund request is stored with `refund_address = attacker_btc_address`.
6. If the DAO/Operator does not call `reject_refund` within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund(utxo_storage_key, None)`.
7. The bridge builds a PSBT paying Alice's 0.1 BTC (minus gas fee) to the attacker's Bitcoin address and submits it to MPC for signing. Alice's BTC is permanently lost.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L602-626)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_refund_finalize(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        btc_pending_info.assert_refund_pending_verify_tx();
        require!(
            btc_pending_info.tx_bytes_with_sign.is_some(),
            "Missing tx_bytes_with_sign"
        );
        self.internal_verify_refund_finalize(tx_id, proof, btc_pending_info)
    }

    /// Remove a leftover refund pending transaction whose refund request is gone
    /// (the refund was already finalized via another candidate, or rejected). Such
    /// a transaction can never confirm, so this only cleans up stale state — it is
    /// rejected while the refund request still exists.
    ///
    /// # Arguments
    ///
    /// * `tx_id` - Pending id of the stale refund transaction to remove.
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn remove_refund_pending_tx_id(&mut self, tx_id: String) {
        self.internal_remove_refund_pending_tx_id(tx_id);
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
