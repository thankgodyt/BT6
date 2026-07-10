### Title
Caller Identity Not Verified in `request_refund` Allows Attacker to Redirect Victim's BTC Refund - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund` accepts a caller-supplied `refund_address` without verifying that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`. Any unprivileged NEAR account can submit a refund request for another user's unfinalized BTC deposit, pointing the refund to an attacker-controlled BTC address. After the `unsafe_refund_timelock_sec` elapses (and if the DAO/Operator fails to reject), the attacker calls `execute_refund` and permanently redirects the victim's BTC.

### Finding Description
`request_refund` is publicly callable (no `#[trusted_relayer]` gate on the method itself, unlike `verify_refund_finalize` and `remove_refund_pending_tx_id` in the same impl block). [1](#0-0) 

Inside `internal_request_refund`, the only caller-identity check is that if `deposit_msg.refund_address` is already set, the supplied `refund_address` must match it. When `deposit_msg.refund_address` is `None` — the common case for users who did not pre-authorize a BTC refund address — the function accepts any `refund_address` from any caller without verifying they are the intended recipient. [2](#0-1) 

`DepositMsg.refund_address` is an `Option<String>`, so deposits without a pre-set refund address are the normal case. [3](#0-2) 

The stored `RefundRequest` records the attacker-supplied `refund_address` verbatim, which is later used by `execute_refund` to build the BTC output. [4](#0-3) 

The `#[trusted_relayer]` decorator on the impl block at line 480 is a configuration annotation; the actual per-method gate is applied only to methods that carry their own `#[trusted_relayer]` attribute (e.g., `verify_refund_finalize` at line 602, `remove_refund_pending_tx_id` at line 622). `request_refund`, `reject_refund`, and `execute_refund` carry no such per-method gate, confirming they are open to any caller. [5](#0-4) [6](#0-5) 

### Impact Explanation
An attacker who observes an unfinalized BTC deposit (one where `verify_deposit` was never called) can permanently redirect the victim's BTC to an attacker-controlled address. The victim loses their entire deposited BTC with no recovery path once `execute_refund` is signed and broadcast. This is a **Critical** impact: significant, permanent theft of user funds.

### Likelihood Explanation
**Medium.** The attack requires:
1. A deposit that was never finalized via `verify_deposit` (e.g., relayer downtime, dust amount, or intentional griefing).
2. The DAO/Operator failing to reject the malicious request within `unsafe_refund_timelock_sec`.

The longer `unsafe_refund_timelock_sec` (applied when `deposit_msg.refund_address` is `None`) gives the DAO a window to reject, but this is an operational safeguard, not a protocol-level guarantee. A monitoring failure, operator downtime, or a coordinated attack across many deposits simultaneously makes exploitation realistic. [7](#0-6) 

### Recommendation
Add a caller-identity check at the start of `internal_request_refund` (or in `request_refund` before delegating):

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id
        || self.acl_has_role(Role::DAO.into(), env::predecessor_account_id())
        || self.acl_has_role(Role::Operator.into(), env::predecessor_account_id()),
    "Only the deposit recipient or a privileged role may request a refund"
);
```

This mirrors the ToyBox fix: verify the caller is the owner named in the authorization structure before acting on their behalf.

### Proof of Concept

1. Alice sends 1 BTC to the deposit address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`.
2. The relayer never calls `verify_deposit` (downtime, dust filter, etc.).
3. Attacker calls:
   ```
   request_refund(
       deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
       refund_address = "attacker_btc_address",
       tx_bytes = <alice's real BTC tx>,
       vout = 0,
       proof = <valid light-client proof>,
       gas_fee = None
   )
   ```
   The Light Client proof is valid (the BTC tx is real), so `request_refund_callback` stores a `RefundRequest` with `refund_address = "attacker_btc_address"`.
4. After `unsafe_refund_timelock_sec` elapses (and if DAO does not reject), attacker calls `execute_refund(utxo_storage_key, None)`.
5. The bridge builds and signs a BTC transaction sending Alice's 1 BTC (minus gas fee) to the attacker's address.
6. `verify_refund_finalize` finalizes the refund; Alice's BTC is permanently gone. [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-483)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    // ── Refund API ──
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L600-605)
```rust
    ///   transaction), and the coinbase fields `coinbase_tx_id` and
    ///   `coinbase_merkle_proof` used to verify the block's coinbase.
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_refund_finalize(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
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

**File:** contracts/satoshi-bridge/src/refund.rs (L222-228)
```rust
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-580)
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
