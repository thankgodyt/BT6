### Title
Missing `refund_address` Validation in `request_refund` Enables Attacker-Triggered Temporary Locking of User BTC Funds - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`request_refund` accepts and stores an arbitrary `refund_address: String` without validating it is a parseable BTC address for the configured chain. The address is only parsed later inside `execute_refund` → `build_refund_output`, where an invalid address causes a panic. Because only one refund request can exist per UTXO, an attacker who knows a victim's `deposit_msg` can front-run the victim's `request_refund` with a garbage `refund_address`, permanently blocking the victim's refund path until a DAO/Operator manually calls `reject_refund`.

### Finding Description
`request_refund` (public, `#[payable]`, no role restriction) accepts `refund_address: String` and passes it through to `request_refund_callback`, which stores it verbatim in a `RefundRequest` without any address-format check: [1](#0-0) 

The address is only validated much later, inside `build_refund_output`: [2](#0-1) 

`Address::parse` panics via `.expect("Invalid refund address")` if the string is empty, malformed, or belongs to a different chain. This panic occurs inside `execute_refund`, reverting all state changes from that call, but leaving the `RefundRequest` intact in storage with the invalid address. Every subsequent `execute_refund` call for the same UTXO will panic identically.

`request_refund_callback` enforces a uniqueness invariant — only one request per UTXO key is allowed: [3](#0-2) 

This means once a request with an invalid address is stored, no legitimate `request_refund` for the same UTXO can succeed.

The `deposit_msg` used to derive the deposit address path is often reconstructable from public BTC chain data (it is hashed to produce the key-derivation path, and the `recipient_id` is typically a known NEAR account). An attacker who can reconstruct the victim's `deposit_msg` can front-run the victim's `request_refund` call with a garbage `refund_address` (e.g., `""`), paying only the anti-spam NEAR deposit.

### Impact Explanation
The victim's BTC UTXO is held in the bridge-controlled MPC address. The refund path is the only mechanism to recover BTC from a deposit that was never finalized via `verify_deposit`. With the refund request stuck on an invalid address, `execute_refund` always panics and the victim cannot recover their BTC until a DAO/Operator calls `reject_refund`. This constitutes attacker-triggered temporary locking of bridged user funds, matching the allowed Medium impact. [4](#0-3) 

### Likelihood Explanation
The attack requires the attacker to know the victim's `deposit_msg` to pass the script-pubkey check in `request_refund_callback`: [5](#0-4) 

The `deposit_msg` includes `recipient_id` (a public NEAR account), and optional fields that are often empty or predictable. For standard deposits (`post_actions: None`, `extra_msg: None`, `safe_deposit: None`, `refund_address: None`), the `deposit_msg` is fully determined by the `recipient_id`, which is observable on-chain or from NEAR indexers. The attacker only needs to pay the NEAR anti-spam deposit (`required_balance_for_request_refund()`). The `request_refund` function has no role restriction and is callable by any account. [6](#0-5) 

### Recommendation
Validate `refund_address` against the configured chain at the start of `internal_request_refund`, before the light-client cross-contract call is scheduled. Reject the call immediately if `Address::parse(refund_address, config.chain.clone())` returns an error. This mirrors the validation already performed in `build_refund_output` and ensures no invalid request is ever stored. [7](#0-6) 

### Proof of Concept
1. Victim deposits BTC to the bridge address derived from `deposit_msg = { recipient_id: "victim.near", ... }`. The deposit is never finalized by a relayer.
2. Attacker reconstructs `deposit_msg` from the victim's NEAR account ID and the BTC transaction.
3. Attacker calls `request_refund(deposit_msg, refund_address="", tx_bytes=<victim_tx>, vout=0, proof=<valid_proof>, gas_fee=None)` with the required NEAR deposit attached.
4. Light-client verification passes (the proof is valid). `request_refund_callback` verifies the script-pubkey matches, finds no existing request, and stores `RefundRequest { refund_address: "", ... }`.
5. Victim calls `request_refund` with a valid address → panics: `"Refund request already exists for this UTXO"`.
6. Anyone calls `execute_refund(utxo_storage_key, None)` → panics inside `build_refund_output`: `"Invalid refund address"`. State is reverted; the stuck request remains.
7. Victim's BTC is locked until DAO/Operator calls `reject_refund(utxo_storage_key)`. [8](#0-7)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L293-308)
```rust
    /// Build a transparent refund output paying `refund_amount` to `refund_address`.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L517-525)
```rust
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );
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
