### Title
Unauthorized Refund Redirection: Any Caller Can Hijack Another User's BTC Deposit Refund - (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` in the satoshi-bridge contains no check that the caller is the legitimate depositor (`deposit_msg.recipient_id`). Any unprivileged NEAR account can call it with a victim's `DepositMsg` and supply an attacker-controlled `refund_address`, causing the bridge's MPC pipeline to send the victim's BTC to the attacker after the timelock elapses.

---

### Finding Description

The deposit address is deterministically derived from the SHA-256 hash of the JSON-serialized `DepositMsg`: [1](#0-0) 

`DepositMsg` contains `recipient_id` (the intended NEAR beneficiary) and an optional `refund_address`: [2](#0-1) 

`request_refund` is a public, payable function (no `#[trusted_relayer]` on the function itself, only `#[pause]`): [3](#0-2) 

Inside `internal_request_refund`, the only `refund_address` validation is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [4](#0-3) 

This check is **only active when `deposit_msg.refund_address` is `Some`**. When it is `None` (the common case for standard deposits), the caller-supplied `refund_address` is accepted unconditionally. There is no check anywhere in `internal_request_refund` or `request_refund_callback` that `env::predecessor_account_id() == deposit_msg.recipient_id`. [5](#0-4) 

The callback stores the attacker-supplied `refund_address` verbatim into the `RefundRequest`: [6](#0-5) 

After the timelock, `execute_refund` (also callable by anyone) builds and submits a PSBT that pays `refund_request.refund_address` — the attacker's BTC address — via the MPC signing pipeline: [7](#0-6) 

---

### Impact Explanation

**Critical — theft of user BTC funds.**

A victim's BTC deposit is permanently redirected to an attacker-controlled Bitcoin address. The victim receives no nBTC (the deposit is consumed by the refund path) and no BTC (it goes to the attacker). The bridge's MPC/Chain Signatures infrastructure signs and broadcasts the malicious refund transaction, making it irreversible once confirmed on-chain.

---

### Likelihood Explanation

**Medium.**

The attack requires three conditions:

1. **`DepositMsg` is reconstructable.** For a standard deposit (`refund_address = None`, no `post_actions`), the `DepositMsg` is `{"recipient_id":"alice.near"}`. An attacker who sees Alice's BTC deposit on-chain and knows her NEAR account ID (public) can trivially reconstruct it and verify it hashes to the observed deposit address.

2. **The deposit is not yet finalized.** The attacker must act before a relayer calls `verify_deposit`. This window can be hours to days depending on confirmation depth and relayer latency.

3. **DAO/Operator does not reject within `unsafe_refund_timelock_sec`.** The longer timelock for requests without a pre-authorized `refund_address` is the only code-level mitigation: [8](#0-7) 

This is a trust-based, not cryptographic, mitigation. An inattentive, overwhelmed, or temporarily offline operator allows the attack to succeed. An attacker can also submit many such requests simultaneously to overwhelm the rejection capacity.

---

### Recommendation

Add a caller-ownership check at the top of `internal_request_refund` in `contracts/satoshi-bridge/src/refund.rs`:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Only the intended recipient can request a refund"
);
```

This is the direct analog of the CryptoPunks fix (`cryptoPunkContract.punkIndexToAddress(tokenId) == item.sellerAddress`): enforce that the entity initiating the refund is the entity that owns the deposit.

Alternatively, if permissionless refund submission is desired (e.g., for relayer automation), require that the `refund_address` be pre-committed inside the `DepositMsg` (`deposit_msg.refund_address` must be `Some`) so the destination cannot be attacker-supplied at request time.

---

### Proof of Concept

1. Alice sends 1 BTC to the deposit address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None }`.
2. The deposit is pending (relayer has not yet called `verify_deposit`).
3. Eve observes Alice's BTC transaction on-chain. She reconstructs Alice's `DepositMsg` (trivial: just `alice.near`'s account ID) and confirms the deposit address matches.
4. Eve calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "alice.near" },
     refund_address = "eve_btc_address",
     tx_bytes = <Alice's raw BTC tx>,
     vout = 0,
     proof = <valid Merkle proof>,
     gas_fee = None
   )
   ```
   attaching the required storage deposit.
5. `internal_request_refund` verifies the BTC transaction via the Light Client (valid), skips the `refund_address` check (because `deposit_msg.refund_address` is `None`), and stores `RefundRequest { refund_address: "eve_btc_address", ... }`.
6. DAO/Operator does not reject within `unsafe_refund_timelock_sec`.
7. Eve (or anyone) calls `execute_refund(utxo_storage_key)`. The bridge builds a PSBT paying `eve_btc_address`, submits it to Chain Signatures, and broadcasts the signed transaction.
8. Alice's 1 BTC (minus gas fee) is confirmed on-chain to Eve's address. Alice receives nothing. [9](#0-8)

### Citations

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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
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
