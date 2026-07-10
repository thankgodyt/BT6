### Title
NEAR Storage Deposit Permanently Locked in Bridge Contract on `request_refund` Callback Failure — (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
`request_refund` requires the caller to attach a NEAR storage deposit. If the subsequent cross-contract callback (`request_refund_callback`) panics — due to failed light-client verification, a race with `verify_deposit`, or a duplicate request — the attached NEAR deposit is permanently locked inside the bridge contract with no retrieval mechanism.

### Finding Description
`request_refund` is a `#[payable]` function that enforces a minimum attached deposit: [1](#0-0) 

The function then schedules a cross-contract call to the BTC light client, followed by a callback: [2](#0-1) 

In NEAR Protocol, once the outer function (`request_refund`) completes without panicking, the attached deposit is transferred to the bridge contract. If the callback subsequently panics, NEAR's state-rollback only undoes storage mutations — it does **not** automatically refund the attached deposit to the original caller.

`request_refund_callback` contains multiple `require!` guards that can panic after the deposit is already held by the contract: [3](#0-2) 

Panic paths include:
- `verify_transaction_inclusion` returning `false` (wrong proof, insufficient confirmations)
- `"UTXO already verified via deposit"` (race with a concurrent `verify_deposit`)
- `"Refund request already exists for this UTXO"` (duplicate concurrent `request_refund`)

After any of these panics, the NEAR deposit remains in the bridge contract. There is no `withdraw_near`, `recover_storage_deposit`, or equivalent function anywhere in the contract to retrieve it. The only NEAR outflows visible in the codebase are 1-yoctoNEAR attachments for `ft_transfer` calls: [4](#0-3) 

No path exists to drain the accumulated NEAR from failed callbacks.

The inline comment in `refund.rs` sizes the required deposit at approximately 2 NEAR: [5](#0-4) 

The public-facing API entry point is: [6](#0-5) 

### Impact Explanation
Every failed `request_refund` call permanently locks ~2 NEAR inside the bridge contract. The depositor has no way to recover it. Over time, this accumulates as an irrecoverable loss of user funds held by the protocol. This matches **Medium** impact: broken callback rollback causing stuck bridge state requiring operator intervention, and harmful smart-contract behavior without direct theft of BTC/nBTC.

### Likelihood Explanation
The failure paths are reachable by any unprivileged NEAR account:
- Submitting a proof before the required number of confirmations is reached (common for impatient users)
- A relayer calling `verify_deposit` for the same UTXO between the user's `request_refund` call and its callback
- Two concurrent `request_refund` calls for the same UTXO (only one succeeds; the other loses its deposit)

These are realistic, non-adversarial scenarios that ordinary bridge users will encounter.

### Recommendation
Refund the attached deposit to the original caller inside `request_refund_callback` when any failure path is taken. Capture `env::predecessor_account_id()` (the original caller) before the async call and pass it to the callback, then use `Promise::new(caller).transfer(env::attached_deposit())` on the failure branch. This mirrors the OpenZeppelin approach cited in the original report: the contract should use its own accumulated balance for operations, or explicitly return deposits when the operation they were meant to fund does not complete.

### Proof of Concept
1. User calls `request_refund` attaching 2 NEAR, with a valid BTC transaction but a proof that references a block with only 5 confirmations when 6 are required.
2. `request_refund` passes its initial checks; the 2 NEAR is transferred to the bridge contract; the light-client cross-contract call is scheduled.
3. The light client returns `false` (insufficient confirmations).
4. `request_refund_callback` hits `require!(is_valid, "verify_transaction_inclusion return false")` and panics.
5. NEAR state rollback undoes the `refund_requests` insertion, but the 2 NEAR deposit remains in the bridge contract.
6. The user has no function to call to recover their 2 NEAR. The bridge contract has no `withdraw_near` or equivalent.
7. Repeating this (e.g., by a griefing attacker who submits many invalid proofs) causes unbounded NEAR accumulation inside the bridge with no recovery path.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L17-26)
```rust
/// Upper bound on the deposit `tx_bytes` accepted by `request_refund`.
///
/// The RefundRequest stores `tx_bytes` verbatim (no truncation — `execute_refund`
/// later decodes them to rebuild the refund tx), so storage grows ~1:1 with tx size:
/// at this cap a request stores ~200 KB ≈ 2 NEAR, which `required_balance_for_request_refund`
/// is sized to cover. The cap also sits safely below the hard gas ceiling: decoding +
/// borsh-storing the tx happens in `request_refund_callback` (only 20 Tgas), which runs
/// out of gas around ~250 KB regardless of the attached deposit. 200 KB is ~1350 signed
/// P2PKH inputs — far above any real deposit (1-2 inputs), incl. large consolidations.
pub(crate) const MAX_REQUEST_REFUND_TX_BYTES: usize = 200_000;
```

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L170-183)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L505-547)
```rust
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
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L12-14)
```rust
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
```

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
