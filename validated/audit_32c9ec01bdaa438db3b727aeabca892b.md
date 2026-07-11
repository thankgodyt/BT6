### Title
Attacker Can Front-Run `request_refund` to Redirect User's BTC Refund to Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is a publicly callable function with no caller-identity check. When a user submits a refund request for an unfinalized deposit where `deposit_msg.refund_address` is `None`, any attacker who observes the pending NEAR transaction can front-run it with the same proof parameters but substitute their own BTC address as `refund_address`. The first registration wins, permanently blocking the legitimate user's request and routing the BTC refund to the attacker.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` (lines 508–535) is a `#[payable]` / `#[pause]`-only function — it carries no `#[trusted_relayer]` attribute on the function itself and no check that the caller is the `deposit_msg.recipient_id` or any party associated with the deposit. [1](#0-0) 

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case — users typically do not embed a refund address in the deposit message used to derive the deposit path), the check is skipped entirely and the caller-supplied `refund_address` is accepted unconditionally.

In `request_refund_callback`, the UTXO key is derived deterministically from the on-chain transaction:

```rust
let utxo_storage_key = generate_utxo_storage_key(tx_id, ...);
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

The first caller to register a refund for a given UTXO wins. Any subsequent call for the same UTXO is rejected. The stored `refund_address` is then used verbatim when `execute_refund` is called — which is itself also publicly callable with no caller restriction: [4](#0-3) 

---

### Impact Explanation

An attacker who front-runs `request_refund` with an attacker-controlled `refund_address` causes the bridge's MPC signing pipeline to construct and broadcast a Bitcoin transaction paying the attacker's address. The legitimate user's BTC deposit is permanently redirected. This is a direct, complete theft of user funds from the bridge's UTXO set.

Even if the DAO/Operator rejects the malicious request during the `unsafe_refund_timelock_sec` window, the attacker can immediately re-front-run the user's next `request_refund` submission, creating a permanent griefing loop that locks the user's BTC indefinitely.

**Allowed impact matched:** *Critical — Significant loss, theft, or permanent locking of user funds.*

---

### Likelihood Explanation

- `request_refund` is publicly callable by any NEAR account with no role or identity restriction.
- All parameters needed to front-run (`deposit_msg`, `tx_bytes`, `vout`, `proof`) are visible in the NEAR transaction mempool before finalization.
- The attack requires no special privilege, no leaked key, and no trusted-role compromise — only the ability to submit a NEAR transaction with higher priority.
- Deposits where `deposit_msg.refund_address` is `None` are the standard case (the field is `skip_serializing_if = "Option::is_none"` and optional by design). [5](#0-4) 

---

### Recommendation

Bind the refund request to the caller's identity. Two options:

1. **Record the requester at registration time** and require that only the original requester (or DAO/Operator) can execute the refund. Store `requester: AccountId` in `RefundRequest` and enforce it in `execute_refund`.

2. **Require `deposit_msg.refund_address` to be set** before `request_refund` is accepted when the caller is not a privileged role. Since the deposit address is derived from the full `deposit_msg` hash (including `refund_address`), a pre-committed refund address cannot be substituted by a front-runner. [6](#0-5) 

---

### Proof of Concept

1. **Victim** sends 0.1 BTC to the deposit address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None }`.
2. The deposit is never finalized (e.g., wrong metadata). Victim calls `request_refund(deposit_msg, "bc1q...alice...", tx_bytes, vout, proof, None)` on NEAR.
3. **Attacker** observes the pending NEAR transaction in the mempool, extracts all parameters, and immediately submits `request_refund(deposit_msg, "bc1q...attacker...", tx_bytes, vout, proof, None)` with higher gas priority.
4. Attacker's transaction is processed first. `refund_requests["{txid}@{vout}"]` is stored with `refund_address = "bc1q...attacker..."`.
5. Victim's transaction reverts: `"Refund request already exists for this UTXO"`. [7](#0-6) 

6. After `unsafe_refund_timelock_sec` elapses (assuming DAO does not intervene), attacker calls `execute_refund("{txid}@{vout}", None)`.
7. Bridge constructs a Bitcoin transaction paying `"bc1q...attacker..."` and submits it to the MPC signing pipeline.
8. Victim's 0.1 BTC (minus gas fee) is sent to the attacker's Bitcoin address. [8](#0-7)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L32-47)
```rust
pub struct RefundRequest {
    pub deposit_msg_json: String,
    pub utxo_storage_key: String,
    pub tx_bytes: Base64VecU8,
    pub vout: usize,
    pub amount: u128,
    pub refund_address: String,
    pub gas_fee: u128,
    pub created_at_sec: u32,
    /// Set once `execute_refund` has built a refund transaction for this request.
    /// While `true` the request is kept (not removed) so `execute_refund` can be
    /// called again to re-create the transaction (e.g. after a consensus branch
    /// change); it is removed only when the refund is finalized in
    /// `verify_refund_finalize`.
    pub executed: bool,
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

**File:** contracts/satoshi-bridge/src/refund.rs (L529-547)
```rust
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
