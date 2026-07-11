### Title
Permissionless `request_refund` Allows Attacker to Register Arbitrary Refund Address, Redirecting User BTC — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `request_refund` entry point is callable by any unprivileged NEAR account and performs no check that the caller is the original depositor. When `deposit_msg.refund_address` is `None`, the caller may supply any BTC address as the refund destination. An attacker who submits `request_refund` before the legitimate user can register their own BTC address for the UTXO, blocking the user's own request and — if the DAO/Operator does not reject the malicious entry within the 14-day `unsafe_refund_timelock_sec` — redirecting the user's BTC to the attacker.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` (lines 510–535) is a `#[payable]` public function with no role guard beyond the optional `gas_fee` check. It accepts a `deposit_msg`, a caller-supplied `refund_address`, and a Merkle proof, then delegates to `internal_request_refund`. [1](#0-0) 

Inside `request_refund_callback` (the async continuation), the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` — the common case for standard deposits — the branch is skipped entirely, and the caller's arbitrary `refund_address` is stored verbatim in the `RefundRequest`. [3](#0-2) 

A duplicate-request guard then blocks any subsequent `request_refund` call for the same UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

So the first caller wins, and the legitimate depositor is locked out until DAO/Operator explicitly rejects the malicious entry.

After the `unsafe_refund_timelock_sec` (14 days, `DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC`), `execute_refund` is also permissionless: [5](#0-4) [6](#0-5) 

The BTC is then sent to whatever `refund_address` was stored in the request — the attacker's address.

---

### Impact Explanation

**Minimum (Medium):** The attacker's malicious `request_refund` permanently occupies the UTXO slot. The legitimate user cannot submit their own refund request until DAO/Operator rejects the malicious one. This is an attacker-triggered temporary locking of bridged BTC funds.

**Maximum (Critical):** If DAO/Operator monitoring fails or is delayed beyond 14 days, the attacker calls `execute_refund`, and the bridge's MPC signing pipeline constructs and broadcasts a Bitcoin transaction paying the attacker's BTC address. The user's deposited BTC is permanently lost. [7](#0-6) 

---

### Likelihood Explanation

- All inputs needed for the attack (`deposit_msg`, `tx_bytes`, Merkle proof) are publicly visible on the Bitcoin blockchain once the deposit confirms.
- The attacker only needs to pay the NEAR storage deposit for `request_refund` (non-refundable but small).
- No privileged role is required.
- The 14-day window is the sole mitigation; it relies entirely on active DAO/Operator monitoring. A single missed alert is sufficient for the attacker to succeed.
- Deposits with `deposit_msg.refund_address = None` are the standard case (the `refund_address` field is `skip_serializing_if = "Option::is_none"`), so the attack surface is broad. [8](#0-7) 

---

### Recommendation

1. **Require caller authorization**: In `request_refund_callback`, verify that `env::predecessor_account_id()` (the original caller, passed through the callback chain) equals `deposit_msg.recipient_id`. Only the intended recipient should be able to register a refund address for their deposit.
2. **Alternatively, require `deposit_msg.refund_address` to always be set**: Eliminate the "unsafe" path entirely by requiring the refund address to be embedded in the deposit message at deposit time, making it immutable and attacker-proof.
3. **Emit a monitoring event on every `request_refund` submission** so off-chain alerting can flag requests where the caller differs from `recipient_id`.

---

### Proof of Concept

1. Alice deposits BTC with `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The deposit fails to finalize (e.g., light-client proof not submitted in time).
2. Attacker Bob observes the confirmed BTC transaction on-chain, extracts `tx_bytes`, `vout`, and reconstructs `deposit_msg` from the OP_RETURN/metadata.
3. Bob calls `request_refund(deposit_msg, "bc1q_BOB_ADDRESS", tx_bytes, vout, proof, None)` before Alice does, paying the required NEAR storage deposit.
4. `request_refund_callback` runs: `deposit_msg.refund_address` is `None`, so the branch at line 154 is skipped. Bob's address is stored as `refund_address` in the `RefundRequest`.
5. Alice calls `request_refund` — it panics at line 544: `"Refund request already exists for this UTXO"`. Alice is blocked.
6. DAO/Operator does not notice within 14 days.
7. Bob calls `execute_refund(utxo_storage_key, None)`. The bridge builds a PSBT spending Alice's deposit UTXO, requests an MPC signature, and broadcasts a Bitcoin transaction paying `bc1q_BOB_ADDRESS`.
8. Alice's BTC is permanently redirected to Bob. [9](#0-8)

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L497-581)
```rust
    pub fn request_refund_callback(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        gas_fee: Option<u128>,
    ) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

        // Verify that the output script matches the deposit address derived from deposit_msg
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
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

        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

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

        true
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
