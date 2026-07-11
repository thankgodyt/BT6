### Title
Unprivileged Attacker Can Redirect BTC/ZEC Refunds to Attacker-Controlled Address by Front-Running `request_refund` — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

When a user's `DepositMsg` has `refund_address: None`, any unprivileged NEAR account can call `request_refund` for that victim's UTXO and supply an attacker-controlled BTC/ZEC address. The contract's duplicate-detection check then permanently blocks the victim from submitting their own refund request. After `unsafe_refund_timelock_sec` elapses without DAO/Operator intervention, `execute_refund` sends the victim's BTC/ZEC to the attacker's address. The victim has no self-rescue path: `reject_refund` is restricted to DAO/Operator.

### Finding Description

**Root cause — missing caller-ownership validation in `request_refund`:**

`internal_request_refund` in `contracts/satoshi-bridge/src/refund.rs` performs two checks before storing a refund request:

1. If `deposit_msg.refund_address` is `Some(addr)`, the provided `refund_address` must equal `addr`.
2. In the callback, the output script of the BTC transaction must match the deposit address derived from `deposit_msg`. [1](#0-0) 

There is **no check** that `env::predecessor_account_id()` is the `deposit_msg.recipient_id` or has any ownership claim over the UTXO. When `deposit_msg.refund_address` is `None`, the first check is skipped entirely, and the caller may supply any BTC/ZEC address as `refund_address`. [2](#0-1) 

**Duplicate-detection blocks the victim:**

Once the attacker's request is stored, the callback enforces:

```
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

The victim's subsequent `request_refund` call for the same UTXO is rejected. This is the direct analog to the external report: a public endpoint accepts data attributed to a UTXO without validating the submitter's ownership, and the duplicate-detection then blocks the legitimate owner.

**Victim cannot self-rescue:**

`reject_refund` requires the caller to be DAO/Operator, or for the UTXO to already be in `verified_deposit_utxo` (which it is not, since `verify_deposit` was never called — that is the entire reason a refund is needed). [4](#0-3) 

**Funds are sent to the attacker after the timelock:**

`execute_refund` is callable by anyone after `unsafe_refund_timelock_sec`. It reads `refund_address` from the stored `RefundRequest` — the attacker's address — and builds the PSBT paying that address. [5](#0-4) [6](#0-5) 

**End-to-end exploit path:**

1. Alice deposits BTC using `DepositMsg { recipient_id: alice, refund_address: None, ... }`. The `LogDepositAddress` event makes the `deposit_msg` public. The BTC transaction is public on-chain.
2. The relayer fails to call `verify_deposit` (network issue, user changed mind, etc.).
3. Bob (attacker) calls `request_refund(alice_deposit_msg, bob_btc_address, tx_bytes, vout, proof, None)`. The `refund_address` check at line 154 is skipped because `deposit_msg.refund_address` is `None`. The Light Client verifies the BTC transaction. The callback stores `RefundRequest { refund_address: bob_btc_address, ... }`.
4. Alice calls `request_refund` with her own address → panics: `"Refund request already exists for this UTXO"`.
5. Alice calls `reject_refund` → panics: `"Only DAO/Operator can reject, or UTXO must be already verified via deposit"`.
6. After `unsafe_refund_timelock_sec`, Bob (or anyone) calls `execute_refund`. The bridge builds a PSBT paying `bob_btc_address` and requests an MPC signature.
7. Alice's BTC is permanently sent to Bob's address.

Even if DAO/Operator eventually rejects Bob's request, Alice must then re-submit her own request and wait another full `unsafe_refund_timelock_sec`. The attacker can repeat the attack immediately after each rejection, indefinitely delaying Alice's refund.

**Scope of affected deposits:**

Only deposits where `deposit_msg.refund_address` is `None` are vulnerable. Deposits with a pre-authorized `refund_address` in the `DepositMsg` are protected by the equality check. However, `refund_address` is an optional field and many users will omit it (e.g., users who did not anticipate needing a refund at deposit time). [7](#0-6) 

### Impact Explanation

**Critical — significant theft of user BTC/ZEC funds.**

The attacker permanently redirects the victim's BTC/ZEC refund to an attacker-controlled address. The victim has no on-chain self-rescue mechanism. The only mitigation is DAO/Operator intervention within `unsafe_refund_timelock_sec`, which is not guaranteed (operator unavailability, monitoring gaps, or the attacker re-submitting after each rejection). This matches: *"Critical. Significant loss, theft, destruction, or permanent locking of user or protocol funds."*

### Likelihood Explanation

**Medium.** The attacker requires:
- Alice's `deposit_msg` (publicly emitted by `get_user_deposit_address` via `LogDepositAddress` event, or trivially guessable when optional fields are `None`: `{recipient_id: alice}`).
- The BTC transaction bytes and Merkle proof (public on the Bitcoin blockchain).
- A storage deposit (small anti-spam fee, not prohibitive).
- To submit before Alice does — the window is large (days to weeks, since Alice may not realize she needs a refund).

No privileged access is required. The attack is repeatable after each DAO/Operator rejection.

### Recommendation

Add a caller-ownership check in `internal_request_refund`. The simplest fix is to require that `env::predecessor_account_id()` equals `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`:

```rust
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.recipient_id
            || self.acl_has_any_role(vec![Role::DAO.into(), Role::Operator.into()], env::predecessor_account_id()),
        "Only the deposit recipient or a privileged role can request a refund without a pre-authorized refund address"
    );
}
```

Alternatively, require that `deposit_msg.refund_address` is always set (non-`None`) at deposit time, removing the open-submission path entirely.

### Proof of Concept

```
// Attacker (bob.near) front-runs Alice's refund:

// 1. Alice's deposit_msg is public (LogDepositAddress event):
//    { recipient_id: "alice.near", refund_address: null }

// 2. Bob calls request_refund with his own BTC address:
bridge.request_refund(
    deposit_msg = { recipient_id: "alice.near", refund_address: null },
    refund_address = "bc1q_BOB_ATTACKER_ADDRESS",
    tx_bytes = <alice's confirmed BTC deposit tx>,
    vout = 0,
    proof = <valid merkle proof>,
    gas_fee = null,
    attached_deposit = required_balance_for_request_refund()
)
// → Succeeds. RefundRequest stored with refund_address = bob's address.

// 3. Alice tries to submit her own request:
bridge.request_refund(
    deposit_msg = { recipient_id: "alice.near", refund_address: null },
    refund_address = "bc1q_ALICE_ADDRESS",
    ...
)
// → PANICS: "Refund request already exists for this UTXO"

// 4. Alice tries to reject Bob's request:
bridge.reject_refund(utxo_storage_key)
// → PANICS: "Only DAO/Operator can reject, or UTXO must be already verified via deposit"

// 5. After unsafe_refund_timelock_sec, Bob calls execute_refund:
bridge.execute_refund(utxo_storage_key, None)
// → Bridge builds PSBT paying bc1q_BOB_ATTACKER_ADDRESS, requests MPC signature.
// → Alice's BTC is sent to Bob's address.
```

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-184)
```rust
    pub(crate) fn internal_request_refund(
        &self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<u128>,
    ) -> Promise {
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }

        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L18-44)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        _chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
    }
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L25-28)
```rust
    // BTC address for refund if deposit is never finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
