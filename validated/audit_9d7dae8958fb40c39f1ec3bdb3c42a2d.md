### Title
Anyone Can Submit a Refund Request with Arbitrary BTC Destination for Any Unfinalized Deposit — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` imposes no restriction on who may call it. When a deposit's `deposit_msg.refund_address` is `None`, the caller freely supplies the BTC destination address. Because the `deposit_msg` is publicly observable on-chain (emitted by `get_user_deposit_address`), an attacker can front-run the legitimate user, register a refund request pointing to the attacker's own BTC address, and — if the DAO/Operator does not reject it within `unsafe_refund_timelock_sec` — drain the user's stuck BTC.

---

### Finding Description

`request_refund` in `bridge.rs` (lines 510–535) is a public, permissionless function:

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
``` [1](#0-0) 

There is no `#[trusted_relayer]` attribute on this function. The impl block carries the macro at the block level, but the pattern throughout the file is unambiguous: functions that are actually relayer-gated carry the attribute **at the function level** (e.g., `verify_refund_finalize` at line 602, `remove_refund_pending_tx_id` at line 622). `request_refund`, `reject_refund`, and `execute_refund` do not. [2](#0-1) 

The only caller-sensitive check inside `request_refund` is the optional `gas_fee` privilege gate; the `refund_address` itself is accepted from any caller without restriction:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [3](#0-2) 

When `deposit_msg.refund_address` is `None` — the common case for standard deposits — the caller's `refund_address` is stored verbatim in the `RefundRequest` with no ownership check: [4](#0-3) 

The `deposit_msg` is publicly observable: `get_user_deposit_address` emits a `LogDepositAddress` event that includes the full `deposit_msg`: [5](#0-4) 

`execute_refund` is equally unrestricted — any account may call it after the timelock: [6](#0-5) 

`resolve_execute_refund_timelock` only uses the caller identity to decide whether to apply the shorter `refund_timelock_sec` (privileged) or the longer `unsafe_refund_timelock_sec` (unprivileged); it does not block unprivileged callers: [7](#0-6) 

---

### Impact Explanation

An attacker who wins the race to `request_refund` for a deposit whose `deposit_msg.refund_address` is `None` can register their own BTC address as the refund destination. Once `unsafe_refund_timelock_sec` elapses without a DAO/Operator rejection, the attacker calls `execute_refund` and the bridge's MPC pipeline constructs and signs a Bitcoin transaction paying the attacker's address. The legitimate depositor's BTC is permanently redirected. This constitutes **unauthorized release of underlying BTC** — a Critical impact class.

---

### Likelihood Explanation

**Medium.** The attack requires:
1. The attacker observes the `LogDepositAddress` event (trivial — public chain data).
2. The deposit is never finalized via `verify_deposit` (realistic: relayer downtime, network issues).
3. The DAO/Operator does not reject the malicious request within `unsafe_refund_timelock_sec`.

The DAO/Operator rejection window is the primary mitigation, but it is an operational control, not a protocol-level guarantee. Any monitoring gap, delayed response, or high-volume spam of refund requests across many UTXOs simultaneously could exhaust the operator's capacity to review and reject in time.

---

### Recommendation

Bind the `refund_address` to the depositor's identity at the protocol level. The simplest fix is to require that `deposit_msg.refund_address` is always `Some(...)` — i.e., the BTC refund destination must be committed to at deposit-address-generation time, before any BTC is sent. Alternatively, require the caller of `request_refund` to be the `deposit_msg.recipient_id` (the NEAR account that was to receive nBTC), so only the intended beneficiary can register a refund address. Either approach eliminates the ability for an arbitrary third party to redirect funds.

---

### Proof of Concept

1. User calls `get_user_deposit_address(deposit_msg)` where `deposit_msg = { recipient_id: "user.near", refund_address: None, ... }`. The bridge emits `LogDepositAddress { deposit_msg, deposit_address }`.
2. User sends BTC to the emitted deposit address. The deposit is never finalized (relayer is down).
3. Attacker reads `deposit_msg` from the `LogDepositAddress` event and the BTC transaction from the Bitcoin chain.
4. Attacker calls:
   ```
   request_refund(
     deposit_msg,
     "attacker_btc_address",
     tx_bytes,
     vout,
     proof,
     None
   )
   ```
   with sufficient attached NEAR. The Light Client verifies the proof; `request_refund_callback` stores `RefundRequest { refund_address: "attacker_btc_address", ... }`.
5. After `unsafe_refund_timelock_sec` elapses (assuming no DAO/Operator rejection), attacker calls `execute_refund(utxo_storage_key, None)`.
6. `finalize_refund_with_psbt` builds a Bitcoin PSBT paying `"attacker_btc_address"` and submits it to the MPC signing pipeline. The user's BTC is sent to the attacker. [8](#0-7)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L600-626)
```rust
    ///   transaction), and the coinbase fields `coinbase_tx_id` and
    ///   `coinbase_merkle_proof` used to verify the block's coinbase.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
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
