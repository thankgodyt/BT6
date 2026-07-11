### Title
Missing Caller Identity Validation in `request_refund` Allows Anyone to Redirect Victim's BTC Refund to Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`internal_request_refund` accepts a caller-supplied `deposit_msg` containing a `recipient_id` field but **never validates that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`**. Any unprivileged NEAR account can submit a refund request for any other user's unfinalized deposit, supplying an attacker-controlled BTC `refund_address`, causing the victim's BTC to be refunded to the attacker.

---

### Finding Description

The `internal_request_refund` function in `refund.rs` performs two checks on the supplied `refund_address`:

1. It verifies the BTC transaction is included in the chain (via Light Client proof).
2. If `deposit_msg.refund_address` is `Some`, it requires the caller-supplied `refund_address` to match. [1](#0-0) 

However, when `deposit_msg.refund_address` is `None` — the common case for users who did not pre-authorize a refund address — **no check is performed to ensure the caller is the `recipient_id` named in the `deposit_msg`**. The `recipient_id` field is accepted verbatim from the caller without any identity validation. [2](#0-1) 

In `request_refund_callback`, the only validation performed is that the BTC output's `script_pubkey` matches the deposit address derived from the `deposit_msg` hash. This confirms the `deposit_msg` corresponds to a real deposit, but it does not confirm the caller has any right to that deposit. [3](#0-2) 

The stored `RefundRequest` records the attacker-supplied `refund_address` as the destination for the BTC refund. [4](#0-3) 

This is the direct analog to the RaptorCast finding: a cryptographic/on-chain proof is verified (Stage 1), but the identity claim embedded in the message payload (`recipient_id`) is never compared against the actual caller (Stage 2).

---

### Impact Explanation

**Critical — theft of user BTC funds.**

When `deposit_msg.refund_address` is `None`, an attacker who knows the victim's `deposit_msg` can:

1. Submit a `request_refund` with the victim's `deposit_msg` and the attacker's own BTC address as `refund_address`.
2. Wait for `unsafe_refund_timelock_sec` to elapse.
3. Call `execute_refund`, which builds a Bitcoin transaction paying the attacker's address.
4. The victim's deposited BTC is transferred to the attacker.

The DAO can reject the request during the timelock, but this requires active monitoring of every refund request and is not a reliable security control. If the DAO misses the window, the funds are permanently lost to the victim. [5](#0-4) 

---

### Likelihood Explanation

**Medium-High.**

- `deposit_msg` parameters are submitted as arguments to public NEAR transactions (`verify_deposit`, `request_refund`). They are visible on-chain to any observer.
- An attacker can monitor the NEAR blockchain for `verify_deposit` calls (which expose the `deposit_msg`) and then immediately submit a competing `request_refund` with their own `refund_address` before the legitimate user does.
- Alternatively, the attacker can front-run the victim's own `request_refund` call, since NEAR transaction ordering is observable.
- No special privileges, keys, or costs are required — only a NEAR account and knowledge of the victim's `deposit_msg`.
- The only mitigation is the `unsafe_refund_timelock_sec` window and DAO vigilance, neither of which is a cryptographic guarantee. [6](#0-5) 

---

### Recommendation

Add an explicit identity check at the start of `internal_request_refund` to ensure the caller is the `recipient_id` named in the `deposit_msg`:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Caller must be the deposit recipient"
);
```

This mirrors the fix recommended in the RaptorCast report: validate the identity claim in the message payload against the authenticated caller before processing the request. [6](#0-5) 

---

### Proof of Concept

**Setup**: Victim creates a deposit with `deposit_msg = { recipient_id: "victim.near", refund_address: None }` and sends 1 BTC to the derived deposit address. The deposit is never finalized (relayer fails).

**Attack**:

1. Attacker observes the NEAR blockchain and finds a `verify_deposit` call (or any other transaction) that exposes `deposit_msg = { recipient_id: "victim.near", refund_address: None }` and the corresponding BTC `tx_bytes`/`proof`.

2. Attacker calls `request_refund` (the public API entry point) with:
   - `deposit_msg`: victim's exact `deposit_msg`
   - `refund_address`: `"attacker_btc_address"`
   - `tx_bytes`, `vout`, `proof`: copied from the victim's deposit transaction

3. The Light Client proof passes (the BTC transaction is real). The `script_pubkey` check passes (the `deposit_msg` hash matches the deposit address). The `refund_address` check is skipped because `deposit_msg.refund_address` is `None`. The request is stored with `refund_address = "attacker_btc_address"`.

4. After `unsafe_refund_timelock_sec` elapses (assuming DAO does not reject), attacker calls `execute_refund`.

5. The bridge constructs a Bitcoin transaction paying 1 BTC (minus gas fee) to `"attacker_btc_address"` and submits it for MPC signing.

6. Victim's 1 BTC is permanently transferred to the attacker. [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L200-228)
```rust
    /// Zcash `execute_refund` entrypoints.
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
