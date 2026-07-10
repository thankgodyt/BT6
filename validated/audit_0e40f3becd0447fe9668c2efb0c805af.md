### Title
Unprivileged Caller Can Submit Refund Request for Any User's Deposit UTXO with Attacker-Controlled Refund Address - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is publicly callable with no check that the caller is the intended deposit recipient (`deposit_msg.recipient_id`). When `deposit_msg.refund_address` is `None` (the common case), any caller can supply an arbitrary `refund_address`. An attacker who front-runs the relayer's `verify_deposit` call can create a refund request that, after the `unsafe_refund_timelock_sec` elapses, routes the victim's BTC to an attacker-controlled address.

---

### Finding Description

`request_refund` is declared inside a `#[trusted_relayer] #[near] impl Contract` block but carries no `#[trusted_relayer]` attribute on the function itself: [1](#0-0) 

Functions that are individually restricted (e.g. `verify_refund_finalize`, `remove_refund_pending_tx_id`) carry the per-function `#[trusted_relayer]` attribute. `request_refund`, `reject_refund`, and `execute_refund` do not, making them callable by any NEAR account.

Inside `internal_request_refund`, the only guard on `refund_address` is: [2](#0-1) 

This check fires only when `deposit_msg.refund_address` is `Some(...)`. When it is `None` — the default for ordinary deposits — the caller's supplied `refund_address` is stored verbatim with no ownership verification: [3](#0-2) 

There is no assertion that `env::predecessor_account_id() == deposit_msg.recipient_id`. The `deposit_msg` is public (emitted via `Event::LogDepositAddress` and observable on-chain), so an attacker can reconstruct it for any victim.

After the `unsafe_refund_timelock_sec` elapses, `execute_refund` (also unrestricted) can be called by anyone, triggering `finalize_refund_with_psbt`, which builds and MPC-signs a Bitcoin transaction paying `refund_request.refund_address` — the attacker's address: [4](#0-3) 

---

### Impact Explanation

If the attacker's `request_refund` lands before the relayer's `verify_deposit`, the victim's deposit UTXO is locked into a refund request pointing to the attacker's BTC address. Once the `unsafe_refund_timelock_sec` passes and `execute_refund` is called, the MPC network signs a transaction sending the victim's BTC to the attacker. The victim receives neither nBTC (no `verify_deposit` was processed) nor their BTC back. This constitutes direct theft of user funds — a Critical impact.

---

### Likelihood Explanation

- `deposit_msg` is public: it is emitted on-chain via `Event::LogDepositAddress` and is derivable from the Bitcoin deposit address.
- The attacker only needs to submit `request_refund` before the relayer submits `verify_deposit`. On NEAR, transaction ordering within a block is observable, enabling front-running.
- The `unsafe_refund_timelock_sec` gives DAO/Operator a window to reject, but the DAO is not guaranteed to be monitoring continuously; if the window passes unnoticed, the attack completes.
- The required NEAR storage deposit is a cost, not a security barrier.

Likelihood: **Medium** (requires front-running the relayer and surviving the DAO rejection window), with **Critical** impact if successful.

---

### Recommendation

Add an ownership check in `request_refund` (or `internal_request_refund`) that ensures the caller is the intended recipient, analogous to the SPTV2 fix:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Only the deposit recipient may request a refund for this UTXO"
);
```

If third-party refund submission must be supported (e.g. for relayers acting on behalf of users), require a cryptographic signature from `deposit_msg.recipient_id` authorizing the specific `refund_address`, or restrict the function to trusted relayers only (add `#[trusted_relayer]` directly on the function) and enforce that relayers validate recipient consent off-chain.

---

### Proof of Concept

1. Victim generates a deposit address via `get_user_deposit_address(deposit_msg)` where `deposit_msg = {recipient_id: "victim.near", refund_address: None, ...}`. The event is emitted on-chain.
2. Victim sends BTC to that address; the transaction confirms on Bitcoin.
3. Attacker observes the `deposit_msg` from the on-chain event and the confirmed BTC transaction.
4. Attacker calls `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)` with a valid Light Client proof — before the relayer calls `verify_deposit`.
5. `request_refund_callback` stores `RefundRequest { refund_address: "attacker_btc_addr", ... }`.
6. The `unsafe_refund_timelock_sec` elapses without DAO intervention.
7. Attacker (or any account) calls `execute_refund(utxo_storage_key, None)`.
8. `finalize_refund_with_psbt` builds a Bitcoin transaction paying `"attacker_btc_addr"` and submits it to the MPC signing pipeline.
9. The signed transaction is broadcast; victim's BTC is transferred to the attacker. The victim receives nothing.

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
