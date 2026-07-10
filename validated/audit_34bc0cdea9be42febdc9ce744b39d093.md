### Title
Attacker Can Frontrun `request_refund` to Redirect Refunds or Permanently Block Legitimate Refund Requests - (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The refund request storage key (`utxo_storage_key`) is derived solely from `{txid}@{vout}`, excluding the `refund_address` parameter. For deposits where `deposit_msg.refund_address` is `None`, any caller can submit a `request_refund` with an arbitrary `refund_address` under the same key. An attacker who observes a pending `request_refund` call can race to register the same UTXO with a malicious `refund_address`, permanently blocking the legitimate user's request and — if the DAO fails to reject within the timelock — redirecting the BTC refund to the attacker's address.

---

### Finding Description

In `request_refund_callback`, the storage key for a refund request is computed as:

```rust
let utxo_storage_key = generate_utxo_storage_key(
    tx_id,
    u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
);
``` [1](#0-0) 

`generate_utxo_storage_key` produces `"{txid}@{vout}"` — the `refund_address` is **not** part of the key:

```rust
pub fn generate_utxo_storage_key(txid: String, vout: u32) -> String {
    format!("{}{}{}", txid, UTXO_STORAGE_KEY_TAG, vout.to_string().as_str())
}
``` [2](#0-1) 

The duplicate guard checks only this key:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

The `refund_address` validation only fires when `deposit_msg.refund_address` is `Some`. When it is `None` — the common case for users who did not pre-authorize a refund address — any caller-supplied `refund_address` is accepted without restriction:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [4](#0-3) 

`request_refund` is a `#[payable]` public function (the attached deposit is explicitly described as an anti-spam fee, not a relayer credential). The `#[trusted_relayer]` attribute on the impl block applies only to functions that carry `#[trusted_relayer]` directly (e.g., `verify_refund_finalize`, `remove_refund_pending_tx_id`); `request_refund`, `reject_refund`, and `execute_refund` do not carry it directly and are publicly callable. [5](#0-4) 

**Attack steps:**

1. User A sends BTC to a deposit address derived from `DepositMsg { recipient_id: "alice", refund_address: None, … }`. The deposit is never finalized.
2. User A submits `request_refund(deposit_msg, "alice_btc_addr", tx_bytes, vout, proof, None)`.
3. Attacker B observes the pending NEAR transaction (or independently discovers the BTC UTXO from the public Bitcoin chain and the `deposit_msg` from a prior `LogDepositAddress` event).
4. Attacker B submits `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)` first.
5. Attacker B's callback runs first; a `RefundRequest` with `refund_address = "attacker_btc_addr"` is stored under `{txid}@{vout}`.
6. User A's callback panics: `"Refund request already exists for this UTXO"`. User A's attached NEAR deposit is consumed and not returned.
7. After `unsafe_refund_timelock_sec` elapses (the longer timelock applied when `deposit_msg.refund_address` is `None`), anyone — including the attacker — can call `execute_refund`, which builds and MPC-signs a Bitcoin transaction paying `"attacker_btc_addr"`.

The `unsafe_refund_timelock_sec` is the only mitigation: it gives the DAO a window to call `reject_refund`. If the

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L529-532)
```rust
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/utils.rs (L16-23)
```rust
pub fn generate_utxo_storage_key(txid: String, vout: u32) -> String {
    format!(
        "{}{}{}",
        txid,
        UTXO_STORAGE_KEY_TAG,
        vout.to_string().as_str()
    )
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
