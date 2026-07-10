### Title
Unpermissioned `request_refund` Allows Attacker to Front-Run Victim's Refund and Redirect BTC to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs, contracts/satoshi-bridge/src/refund.rs)

### Summary
`request_refund` is a public function with no check that the caller is the `deposit_msg.recipient_id`. Any NEAR account can submit a refund request for any unfinalized deposit, supplying an arbitrary `refund_address`. Because a duplicate-request guard blocks a second request for the same UTXO, the attacker's malicious registration permanently prevents the victim from filing their own refund. After the `unsafe_refund_timelock_sec` window (14 days by default), the attacker can call `execute_refund` and redirect the victim's BTC to the attacker's address.

### Finding Description
`request_refund` in `bridge.rs` is decorated with `#[pause(except(roles(Role::DAO)))]` but carries no caller-identity check:

```rust
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
) -> Promise {
    if gas_fee.is_some() { /* only gas_fee is role-gated */ }
    self.internal_request_refund(deposit_msg, refund_address, ...)
}
```

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(msg_refund_address == &refund_address, ...);
}
```

When `deposit_msg.refund_address` is `None` (the common case for standard deposits), the caller may supply any BTC address. There is no `require!(env::predecessor_account_id() == deposit_msg.recipient_id, ...)` check anywhere in the call chain.

In `request_refund_callback`, the duplicate guard then permanently blocks a second request for the same UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is also public and callable by anyone:

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

The only safety net is that DAO/Operator can call `reject_refund` within the 14-day window. If they miss it, the attacker's `execute_refund` call builds a Bitcoin transaction paying the attacker's address and submits it to the MPC signing pipeline.

### Impact Explanation
- **Immediate (Medium):** The attacker's malicious `RefundRequest` occupies the UTXO slot, permanently blocking the victim from filing their own refund. The victim's BTC is locked until DAO/Operator actively rejects the request.
- **Escalated (Critical):** If DAO/Operator fails to reject within `unsafe_refund_timelock_sec` (14 days), the attacker calls `execute_refund`, the MPC service signs a transaction paying the attacker's BTC address, and the victim's deposited BTC is permanently stolen. This is a direct, significant loss of user funds.

### Likelihood Explanation
All information needed by the attacker is public: the victim's `deposit_msg` is derivable from the deposit address (logged via `Event::LogDepositAddress`), the BTC transaction is on-chain, and the Merkle proof can be constructed from any Bitcoin node. The attacker only needs to call `request_refund` before the victim does — a straightforward front-run on NEAR. The 14-day window is long enough that a monitoring gap is realistic, especially for less-active deposits.

### Recommendation
Add a caller-identity check in `request_refund` (or `internal_request_refund`) that requires the caller to be the `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`:

```rust
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.recipient_id,
        "Only the deposit recipient may supply a refund address"
    );
}
```

Alternatively, require that `deposit_msg.refund_address` always be pre-set (non-`None`) so the refund address is committed at deposit time and cannot be overridden by a third party.

### Proof of Concept
1. Victim deposits BTC to the bridge-derived address for their `deposit_msg` (with `refund_address: None`). The relayer never calls `verify_deposit` (e.g., due to a bug or the deposit being below the minimum).
2. Attacker observes the victim's BTC transaction on-chain and reconstructs `deposit_msg` from the logged deposit address event.
3. Attacker calls `request_refund(deposit_msg, attacker_btc_address, tx_bytes, vout, proof, None)` with a valid storage deposit attached.
4. `request_refund_callback` verifies the transaction inclusion proof, confirms the output script matches the deposit address, and stores `RefundRequest { refund_address: attacker_btc_address, ... }`.
5. Victim attempts `request_refund` — it panics: `"Refund request already exists for this UTXO"`.
6. DAO/Operator does not notice the malicious request within 14 days.
7. Attacker calls `execute_refund(utxo_storage_key, None)`. The timelock has passed; `build_refund_output` constructs a `TxOut` paying `attacker_btc_address`; the MPC service signs and broadcasts the transaction.
8. Victim's BTC is transferred to the attacker's address. The victim has no recourse. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-548)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

```
