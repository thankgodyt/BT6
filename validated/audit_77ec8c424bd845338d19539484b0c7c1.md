### Title
Any User Can Submit a Refund Request for Any Deposit with an Arbitrary BTC Refund Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary
The `request_refund` function contains no ownership check: any NEAR account can submit a refund request for any unfinalized deposit transaction and supply an arbitrary BTC address as the refund destination. This is the direct analog of STK-2 — just as the Staker contract let users stake on behalf of any address, the bridge lets users initiate a refund on behalf of any depositor, redirecting the underlying BTC to an attacker-controlled address.

---

### Finding Description
`request_refund` is a public, permissionless entry point. Its internal implementation `internal_request_refund` accepts a caller-supplied `refund_address` and a `deposit_msg` that identifies the victim's deposit (via `recipient_id`). The only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

This guard is only active when the original `deposit_msg` already contains a `refund_address`. When `deposit_msg.refund_address` is `None` — the common case for standard deposits — the caller's arbitrary `refund_address` is accepted without any check.

The callback `request_refund_callback` verifies that the transaction output matches the deposit address derived from `deposit_msg`, confirming the UTXO is real:

```rust
require!(
    deposit_script_pubkey == output.script_pubkey,
    "Output script_pubkey does not match deposit address"
);
``` [2](#0-1) 

But it never checks that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. The refund request is then stored with the attacker-supplied `refund_address`:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [3](#0-2) 

After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is also permissionless — any caller can trigger it:

```rust
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
}
``` [4](#0-3) 

The longer `unsafe_refund_timelock_sec` is applied precisely because the refund address was not pre-authorized in the deposit message, giving DAO/Operator a window to reject. However, no on-chain ownership enforcement exists; the entire defense relies on off-chain operator vigilance.

---

### Impact Explanation
If the DAO/Operator fails to reject the malicious refund request within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund` and the bridge's MPC pipeline builds and signs a Bitcoin transaction paying the victim's deposited BTC to the attacker's address. The victim's BTC is permanently lost. This constitutes **significant theft of user funds** — a Critical allowed impact.

---

### Likelihood Explanation
The attack requires:
1. A deposit that was never finalized (relayer outage, stuck transaction, or deliberate griefing).
2. The attacker to front-run or race the refund window before the DAO/Operator rejects.

Relayer outages and stuck deposits are realistic operational events. The `unsafe_refund_timelock_sec` window is finite and operator monitoring is off-chain, making this a realistic Medium-likelihood path to a Critical outcome.

---

### Recommendation
Add an on-chain ownership check inside `internal_request_refund` (or `request_refund_callback`) that asserts the caller is the `recipient_id` encoded in `deposit_msg`:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Only the deposit recipient may request a refund"
);
```

Alternatively, if third-party refund submission must be supported, require that `deposit_msg.refund_address` is always pre-set (non-`None`) so the BTC destination is committed at deposit time and cannot be overridden by an attacker.

---

### Proof of Concept

1. **Victim** sends BTC to the deposit address derived from `deposit_msg { recipient_id: "victim.near", refund_address: None, ... }`.
2. The relayer is temporarily offline; `verify_deposit` is never called.
3. **Attacker** calls:
   ```
   request_refund(
       deposit_msg = { recipient_id: "victim.near", refund_address: None, ... },
       refund_address = "attacker_btc_address",
       tx_bytes = <victim's deposit tx>,
       vout = 0,
       proof = <valid inclusion proof>,
       gas_fee = None,
   )
   ```
   with the required NEAR storage deposit attached.
4. `request_refund_callback` verifies the transaction inclusion and that the output script matches the deposit address — both pass. It stores `RefundRequest { refund_address: "attacker_btc_address", ... }`.
5. After `unsafe_refund_timelock_sec` elapses (DAO/Operator did not reject), attacker calls `execute_refund(utxo_storage_key, None)`.
6. The bridge builds a PSBT spending the victim's deposit UTXO, paying `attacker_btc_address`. MPC signs it. The victim's BTC is transferred to the attacker. [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L497-580)
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
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L582-589)
```rust
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```
