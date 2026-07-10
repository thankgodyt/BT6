### Title
Unprivileged Caller Can Pre-Register a `RefundRequest` for Any Deposit UTXO with an Attacker-Controlled `refund_address`, Blocking Legitimate Refunds and Enabling Fund Redirection — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is a permissionless entry-point. When `deposit_msg.refund_address` is `None` (the common case for standard deposits), any NEAR account can submit a refund request for any unfinalized deposit UTXO and supply an arbitrary `refund_address`. Because the contract enforces a strict one-request-per-UTXO invariant, the first caller wins: a subsequent legitimate call for the same UTXO is rejected. The attacker's request then sits in state for up to 14 days (`unsafe_refund_timelock_sec`), after which anyone can call `execute_refund` to route the BTC to the attacker's address. The DAO must actively intervene to reject the malicious request before that window closes; if it does not, the victim's BTC is permanently redirected.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` (lines 510–535) is callable by any NEAR account. It accepts a `deposit_msg`, `refund_address`, `tx_bytes`, `vout`, and a Merkle proof. All of these are public information: `deposit_msg` is emitted on-chain when `get_user_deposit_address` is called, and `tx_bytes` plus the Merkle proof are available from the Bitcoin blockchain. [1](#0-0) 

Inside `internal_request_refund` in `contracts/satoshi-bridge/src/refund.rs` (lines 137–184), the only check on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the check is skipped entirely and the caller-supplied `refund_address` is stored verbatim.

In `request_refund_callback` (lines 497–581), the contract enforces a hard uniqueness constraint:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

Once the attacker's request is stored, no other caller can create a competing request for the same UTXO. The stored `refund_address` is later used without re-validation in `finalize_refund_with_psbt` → `build_refund_output` to construct the Bitcoin transaction that pays out the deposit. [4](#0-3) 

The `unsafe_refund_timelock_sec` (default 14 days) is the only guard:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [5](#0-4) 

If the DAO does not call `reject_refund` within 14 days, `execute_refund` becomes callable by anyone and the BTC is sent to the attacker's address.

---

### Impact Explanation

**Immediate impact (certain):** The legitimate depositor is blocked from filing their own refund request. Their BTC is stuck in the bridge's MPC-controlled deposit address until the DAO intervenes. This is a stuck bridge state requiring operator intervention.

**Delayed impact (conditional on DAO inaction):** After `unsafe_refund_timelock_sec` elapses, `execute_refund` is permissionless. The MPC network signs a Bitcoin transaction paying the attacker's `refund_address`. The victim's BTC is permanently redirected — a critical loss of user funds.

This maps to the allowed impact categories:
- **Medium**: Attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention.
- **Critical** (if DAO is unresponsive): Unauthorized release of bridge-controlled BTC to an attacker address.

---

### Likelihood Explanation

All inputs required by the attacker are public:
- `deposit_msg` is emitted in the `LogDepositAddress` event when `get_user_deposit_address` is called.
- `tx_bytes` and the Merkle proof are available from any Bitcoin node.
- The only cost is the 2 NEAR anti-spam deposit (non-refunded), which is economically rational for any deposit above a few hundred dollars of BTC.

The attack window is the entire period between a BTC deposit landing on-chain and the relayer calling `verify_deposit`. For deposits that are never finalized (the exact scenario `request_refund` is designed for), this window is indefinite. Any on-chain observer can front-run the legitimate user's `request_refund` call.

---

### Recommendation

1. **Bind the refund request to the caller**: Store `env::predecessor_account_id()` in `RefundRequest` and require that only the original requester (or DAO/Operator) can call `execute_refund` for requests where `deposit_msg.refund_address` is `None`.

2. **Allow the legitimate depositor to override**: Permit the NEAR account named in `deposit_msg.recipient_id` to replace an existing refund request's `refund_address`, or to reject a third-party request without DAO involvement.

3. **Alternatively, require `deposit_msg.refund_address` to be non-`None`**: Enforce that a refund address must be pre-committed in the `deposit_msg` (and thus baked into the deposit address derivation), eliminating the caller-supplied address path entirely.

---

### Proof of Concept

1. Alice deposits BTC to the address derived from her `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The relayer fails to call `verify_deposit` (e.g., the deposit is below `min_deposit_amount`).

2. Attacker observes the `LogDepositAddress` event, retrieves `deposit_msg`, fetches `tx_bytes` and the Merkle proof from Bitcoin.

3. Attacker calls:
   ```
   request_refund(
     deposit_msg = alice's deposit_msg,
     refund_address = "attacker_btc_address",
     tx_bytes = ...,
     vout = 0,
     proof = ...,
     gas_fee = None
   )
   ```
   attaching 2 NEAR. Light Client verification passes. `request_refund_callback` stores `RefundRequest { refund_address: "attacker_btc_address", ... }`.

4. Alice tries to call `request_refund` with her own BTC address. The callback panics: `"Refund request already exists for this UTXO"`. Alice is blocked.

5. After 14 days, attacker (or anyone) calls `execute_refund("txid@0", None)`. The bridge builds a Bitcoin transaction paying `attacker_btc_address` and requests an MPC signature. Alice's BTC is gone. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L496-581)
```rust
    #[private]
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
