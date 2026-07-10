### Title
Unauthenticated `request_refund` Allows Any Caller to Redirect Victim's BTC to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund` performs no check that the caller is the original depositor (`deposit_msg.recipient_id`). Any NEAR account can submit a refund request for any unprocessed BTC deposit and supply an attacker-controlled Bitcoin address as the refund destination. After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is also permissionless, completing the theft.

### Finding Description
The `request_refund` entry point is publicly callable with no ownership check:

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
    gas_fee: Option<u128>,
) -> Promise {
``` [1](#0-0) 

The callback that finalises the request enforces only two things: (1) the BTC transaction is confirmed on-chain, and (2) if `deposit_msg.refund_address` is already set, the supplied `refund_address` must match it. When `deposit_msg.refund_address` is `None`, the caller's arbitrary `refund_address` is stored verbatim with no further restriction:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

There is no `require!(env::predecessor_account_id() == deposit_msg.recipient_id, ...)` anywhere in `request_refund` or its callback. The `deposit_msg` is fully public — it is hashed to derive the deposit address and is observable on-chain — so any attacker can reconstruct it for any victim deposit.

After the request is stored, `execute_refund` is also permissionless:

```rust
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
}
``` [3](#0-2) 

The only gate is the `unsafe_refund_timelock_sec` (default 14 days), which is an operational window for DAO/Operator to reject — not a cryptographic ownership proof:

```rust
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
``` [4](#0-3) 

### Impact Explanation
An attacker who successfully races or outlasts the DAO/Operator review window causes the bridge's MPC signing pipeline to construct and broadcast a Bitcoin transaction paying the victim's deposited BTC to the attacker's address. The victim's BTC is permanently lost. This is a direct, on-chain theft of user funds — **Critical** under the allowed impact scope ("Significant loss, theft, destruction, or permanent locking of user or protocol funds").

### Likelihood Explanation
- The `deposit_msg` is public (hashed to derive the deposit address; observable from the BTC transaction or NEAR events).
- Any deposit that has not yet been finalised via `verify_deposit` is a valid target. Deposits can remain unprocessed due to relayer downtime, amounts below the minimum, or deliberate griefing.
- The attacker only needs to attach the required NEAR storage deposit and wait 14 days. No special role or key is required.
- The DAO/Operator rejection window is a social/operational control, not a protocol guarantee; it can be missed during holidays, incidents, or if many requests are submitted simultaneously to overwhelm reviewers.

Likelihood: **Medium** (requires an unprocessed deposit and patience, but no privileged access).

### Recommendation
Add an ownership check at the start of `request_refund` (or inside `internal_request_refund`) that asserts the caller is the intended recipient:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Only the deposit recipient may request a refund"
);
```

Alternatively, if third-party refund submission must be supported (e.g., for relayers acting on behalf of users), require that `deposit_msg.refund_address` is pre-set (non-`None`) so the destination is committed at deposit time and cannot be overridden by the caller.

### Proof of Concept
1. Alice sends 0.01 BTC to the bridge deposit address derived from her `deposit_msg` (`recipient_id = alice.near`, `refund_address = None`). The deposit is not yet processed by a relayer.
2. Eve observes the BTC transaction on-chain, reconstructs Alice's `deposit_msg`, and calls:
   ```
   request_refund(
       deposit_msg  = alice_deposit_msg,   // recipient_id = alice.near, refund_address = None
       refund_address = "eve_btc_address",
       tx_bytes     = <alice's raw BTC tx>,
       vout         = 0,
       proof        = <valid merkle proof>,
       gas_fee      = None,
   )
   ```
   with the required NEAR storage deposit attached.
3. `request_refund_callback` verifies the BTC proof and stores the request with `refund_address = "eve_btc_address"`. No caller check fires because `deposit_msg.refund_address` is `None`.
4. After 14 days, Eve calls `execute_refund(utxo_storage_key)`. The bridge builds a PSBT spending Alice's UTXO to `"eve_btc_address"`, requests an MPC signature, and broadcasts the transaction.
5. Alice's 0.01 BTC (minus gas fee) arrives at Eve's Bitcoin address. Alice receives nothing. [5](#0-4) [6](#0-5)

### Citations

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

**File:** contracts/satoshi-bridge/src/config.rs (L9-9)
```rust
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
