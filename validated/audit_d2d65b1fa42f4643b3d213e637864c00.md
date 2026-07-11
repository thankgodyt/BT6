### Title
Refund Frontrunning via Unchecked `refund_address` When `deposit_msg.refund_address` Is `None` - (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

When a user deposits BTC using a `DepositMsg` with `refund_address: None`, any unprivileged NEAR account can call `request_refund` and supply an arbitrary attacker-controlled BTC address as the `refund_address`. Because the contract only validates `refund_address` against `deposit_msg.refund_address` when the latter is `Some`, the check is entirely skipped for the `None` case. An attacker who front-runs the legitimate `request_refund` call can register a malicious refund destination, and if the DAO does not reject the request within the `unsafe_refund_timelock_sec` window, the BTC is sent to the attacker.

---

### Finding Description

`request_refund` is a permissionless function (no `#[trusted_relayer]` guard on the function itself) callable by any NEAR account. [1](#0-0) 

Inside `internal_request_refund`, the only ownership check is: [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the `if let Some(...)` branch is never entered, so the caller-supplied `refund_address` is accepted without any validation. The `RefundRequest` is then stored with that unchecked address: [3](#0-2) 

The `DepositMsg` used to derive the deposit address is fully observable: `get_user_deposit_address` emits a `LogDepositAddress` event containing the complete `deposit_msg`, and the BTC transaction is public on-chain. [4](#0-3) 

The `unsafe_refund_timelock_sec` (default 14 days) is the only mitigation — it gives the DAO a window to call `reject_refund`. However, this is an operational control, not a cryptographic one. [5](#0-4) [6](#0-5) 

---

### Impact Explanation

**Scenario A — Theft (if DAO is unresponsive):** After `unsafe_refund_timelock_sec` passes without DAO rejection, the attacker calls `execute_refund`. The bridge builds a PSBT paying the attacker's BTC address and signs it via MPC. The user's deposited BTC is permanently redirected to the attacker. [7](#0-6) 

**Scenario B — Permanent griefing (if DAO is active):** Even if the DAO rejects the malicious request, only one refund request per UTXO can exist at a time ("Refund request already exists for this UTXO"). The attacker can immediately re-submit after each rejection, creating an indefinite front-running loop that prevents the legitimate user from ever reclaiming their BTC through the refund path — permanently locking the funds if the relayer also never calls `verify_deposit`. [8](#0-7) 

This matches the **Medium** allowed impact: *attacker-triggered temporary locking of bridged funds* (Scenario B) and potentially **Critical** *significant loss or theft of user funds* (Scenario A).

---

### Likelihood Explanation

All information needed to execute the attack is publicly available:
- The `deposit_msg` is emitted in the `LogDepositAddress` event when the user calls `get_user_deposit_address`.
- The BTC transaction bytes and Merkle proof are observable on the Bitcoin blockchain.
- `request_refund` requires only a small non-refundable NEAR storage deposit as a cost barrier.

The attacker simply monitors NEAR events for `LogDepositAddress` entries with `refund_address: None`, watches for the corresponding BTC transaction to confirm, and submits `request_refund` before the legitimate user. This is a straightforward NEAR transaction race with no special privileges required.

---

### Recommendation

When `deposit_msg.refund_address` is `None`, require that `env::predecessor_account_id()` matches `deposit_msg.recipient_id` (or a pre-registered owner), so only the intended recipient can register an arbitrary refund address. Alternatively, disallow `request_refund` entirely when `deposit_msg.refund_address` is `None` and require users to always pre-commit a refund address in the `DepositMsg` before sending BTC.

```diff
// in internal_request_refund, after the existing refund_address check:
 if let Some(msg_refund_address) = &deposit_msg.refund_address {
     require!(
         msg_refund_address == &refund_address,
         "refund_address does not match deposit_msg.refund_address"
     );
+} else {
+    require!(
+        env::predecessor_account_id() == deposit_msg.recipient_id,
+        "Only the deposit recipient can specify a refund address when none was pre-committed"
+    );
 }
```

---

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: alice, refund_address: None, ... })`. The contract emits `LogDepositAddress` with the full `deposit_msg`.
2. Alice sends 1 BTC to the returned deposit address. The transaction confirms on Bitcoin.
3. The relayer is slow or down; `verify_deposit` is never called.
4. Attacker observes the `LogDepositAddress` event and the BTC transaction. Attacker calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: alice, refund_address: None, ... },  // exact msg from event
     refund_address = "attacker_btc_address",
     tx_bytes = <alice's BTC tx>,
     vout = 0,
     proof = <valid merkle proof>,
     gas_fee = None
   )
   ```
5. `internal_request_refund` checks `deposit_msg.refund_address` — it is `None`, so the `if let Some(...)` block is skipped. The `RefundRequest` is stored with `refund_address = "attacker_btc_address"`.
6. Alice tries to call `request_refund` herself — it fails: *"Refund request already exists for this UTXO"*.
7. After 14 days (if DAO does not reject), attacker calls `execute_refund`. The bridge builds and MPC-signs a transaction paying `attacker_btc_address`. Alice's BTC is gone. [9](#0-8) [10](#0-9)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-183)
```rust
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-227)
```rust
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L12-28)
```rust
pub struct DepositMsg {
    // The NEAR account receiving nBTC.
    pub recipient_id: AccountId,
    // Parameters for executing ft_transfer_call after successful nBTC minting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    // Used to support other dApps extending based on verify_deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
    // Replacment for the legacy post_actions to support safer cross-contract calls.
    // If this field is present, the legacy post_actions field must be None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_deposit: Option<SafeDepositMsg>,
    // BTC address for refund if deposit is never finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
