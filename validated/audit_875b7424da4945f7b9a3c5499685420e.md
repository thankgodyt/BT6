### Title
Unrestricted `request_refund` + `execute_refund` Allows Any Caller to Redirect BTC Refunds to Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` and `execute_refund` carry no per-function access control. When a deposit was made with `deposit_msg.refund_address = None`, any NEAR account can call `request_refund` and supply an arbitrary attacker-controlled BTC address as `refund_address`. After the `unsafe_refund_timelock_sec` window (14 days), the same attacker calls `execute_refund` to trigger the MPC-signed refund transaction, sending the deposited BTC to their own address instead of the legitimate depositor's.

---

### Finding Description

**Step 1 — `request_refund` is callable by anyone.**

The function sits in a `#[trusted_relayer] #[near] impl Contract` block but carries no `#[trusted_relayer]` attribute at the function level. Functions that are genuinely restricted (e.g., `verify_refund_finalize`, `remove_refund_pending_tx_id`) carry the per-function attribute; `request_refund` and `execute_refund` do not. The inline documentation confirms the intent: *"After the timelock period, anyone can call `execute_refund` to initiate the return."* [1](#0-0) 

**Step 2 — When `deposit_msg.refund_address` is `None`, the caller freely chooses the BTC destination.**

`internal_request_refund` only enforces address equality when the deposit message already contains a pre-authorized address. When it is `None`, the caller-supplied `refund_address` is stored verbatim. [2](#0-1) 

The stored value becomes the BTC output destination in `finalize_refund_with_psbt` → `build_refund_output`. [3](#0-2) 

**Step 3 — A duplicate request is blocked, so the attacker who submits first wins.**

`request_refund_callback` rejects any second request for the same UTXO: [4](#0-3) 

If the attacker submits before the legitimate depositor, the depositor's own `request_refund` call will revert with *"Refund request already exists for this UTXO"*.

**Step 4 — `execute_refund` is also callable by anyone after the timelock.** [5](#0-4) 

The timelock for the `refund_address = None` path is `unsafe_refund_timelock_sec` (default 14 days): [6](#0-5) 

**Step 5 — The only mitigation is DAO/Operator rejection, which is not guaranteed.**

`reject_refund` requires `Role::DAO` or `Role::Operator`: [7](#0-6) 

If the operator is offline, slow, or overwhelmed, the 14-day window expires and the attacker calls `execute_refund` unchallenged.

---

### Impact Explanation

Once `execute_refund` is called, `finalize_refund_with_psbt` builds a PSBT spending the deposit UTXO and paying `refund_amount` (deposit minus gas fee) to the attacker's BTC address. The MPC network signs it, the signed transaction is broadcast, and the BTC is irreversibly transferred to the attacker. [8](#0-7) 

The legitimate depositor loses their BTC permanently. This is unauthorized release of underlying BTC — **Critical** potential impact.

---

### Likelihood Explanation

- The `deposit_msg` is observable: the bridge emits a `LogDepositAddress` event containing the full `deposit_msg` whenever `get_user_deposit_address` is called, and the BTC transaction itself is public on-chain.
- Unfinalized deposits (below `min_deposit_amount`, wrong NEAR account, etc.) are common edge cases.
- The attacker only needs to pay a small NEAR storage deposit and wait 14 days.
- The DAO/Operator must actively monitor and reject every suspicious refund request within the window — a liveness assumption that can fail.

Likelihood: **Medium**.

---

### Recommendation

1. **Bind `refund_address` to the depositor's identity**: require that the caller of `request_refund` is the `deposit_msg.recipient_id`, or require `deposit_msg.refund_address` to be pre-set (non-`None`) for permissionless refund requests.
2. **Restrict `request_refund` to whitelisted relayers** (add `#[trusted_relayer]` at the function level, consistent with `verify_refund_finalize`), so only trusted parties can submit refund requests on behalf of users.
3. As a defense-in-depth measure, emit a prominent on-chain event when a refund request is submitted with a caller-supplied address, to aid monitoring.

---

### Proof of Concept

1. User sends 0.01 BTC to the deposit address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The deposit is never finalized (e.g., amount below `min_deposit_amount`).
2. Attacker observes the `LogDepositAddress` event, obtains `deposit_msg` and the BTC `tx_bytes` + Merkle proof from the BTC light client.
3. Attacker calls:
   ```
   request_refund(
     deposit_msg,
     refund_address = "attacker_btc_address",
     tx_bytes, vout, proof,
     gas_fee = None
   )
   ```
   with a small NEAR storage deposit attached. The callback verifies the proof and stores the `RefundRequest` with `refund_address = "attacker_btc_address"`.
4. Alice attempts `request_refund` with her own BTC address — it reverts: *"Refund request already exists for this UTXO"*.
5. DAO/Operator does not reject within 14 days.
6. Attacker calls `execute_refund(utxo_storage_key, None)`. The bridge builds a PSBT paying `refund_amount` to `"attacker_btc_address"`, the MPC network signs it, and the BTC is broadcast to the attacker's address.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L544-568)
```rust
    pub fn reject_refund(&mut self, utxo_storage_key: String) {
        let caller = env::predecessor_account_id();
        let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
            || self.acl_has_role(Role::Operator.into(), caller);
        // `execute_refund` also inserts the UTXO into `verified_deposit_utxo` (to block a
        // later deposit) while keeping the request with `executed == true`. That membership
        // must NOT open the permissionless reject path, otherwise anyone could cancel an
        // in-flight refund — so only treat the UTXO as "already deposited" when the request
        // was not executed by us, i.e. a real `verify_deposit` finalized it.
        let executed = self
            .data()
            .refund_requests
            .get(&utxo_storage_key)
            .map(|r| RefundRequest::from(r).executed)
            .unwrap_or(false);
        let is_already_deposited = !executed
            && self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key);
        require!(
            is_privileged || is_already_deposited,
            "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
        );
        self.internal_reject_refund(utxo_storage_key);
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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```
