### Title
Unchecked Caller Identity in `request_refund` Allows Attacker to Redirect Any User's BTC Refund to Arbitrary Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund` does not verify that the caller is the owner of the deposit being refunded. When `deposit_msg.refund_address` is `None` (standard deposits), any unprivileged caller can submit a refund request for any valid deposit and supply an arbitrary attacker-controlled BTC address. This is the direct bridge analog of the ToyBox `primarySaleWithPermit` bug: a signed authorization (the `deposit_msg`) is accepted without verifying that the caller is the party the authorization belongs to.

### Finding Description
In `contracts/satoshi-bridge/src/api/bridge.rs`, `request_refund` is a public, payable function:

```rust
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    tx_bytes: Base64VecU8,
    vout: usize,
    proof: TxInclusionProof,
    gas_fee: Option<U128>,
) -> Promise {
``` [1](#0-0) 

The only identity-related check is inside `internal_request_refund`:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

This check only fires when the user pre-encoded a `refund_address` inside the `deposit_msg`. For standard deposits where `deposit_msg.refund_address` is `None`, the branch is skipped entirely and **any caller may supply any BTC address**. There is no assertion that `env::predecessor_account_id()` equals the NEAR account encoded in `deposit_msg` (the deposit owner).

The callback that stores the request also performs no caller-identity check: [3](#0-2) 

The stored `RefundRequest` records the attacker-supplied `refund_address` verbatim. After `unsafe_refund_timelock_sec` elapses, `execute_refund` is also permissionless and will build and sign a Bitcoin transaction paying that address. [4](#0-3) 

### Impact Explanation
An attacker who observes a victim's unfinalized BTC deposit on-chain (or learns the `deposit_msg` from any public source such as a dApp UI, transaction memo, or prior `request_refund` call) can:

1. Call `request_refund` with the victim's `deposit_msg` and the attacker's own BTC address.
2. Wait for `unsafe_refund_timelock_sec` to elapse.
3. Call `execute_refund` to trigger MPC signing of a refund transaction paying the attacker's address.

The victim's deposited BTC is permanently redirected to the attacker. This matches **Critical – significant loss of user funds**.

### Likelihood Explanation
**Medium.** The attack requires:
- Knowledge of the victim's `deposit_msg` (public or observable).
- The deposit to remain unfinalized (relayer has not called `verify_deposit`).
- DAO/Operator to fail to reject the malicious request within `unsafe_refund_timelock_sec`.

The DAO rejection window is the primary mitigation, but it is an operational control, not a cryptographic one. A busy or inattentive DAO, a large volume of refund requests, or a targeted attack timed around DAO downtime all raise the practical likelihood.

### Recommendation
Add a caller-identity check when `deposit_msg.refund_address` is `None`. The simplest fix is to require that `env::predecessor_account_id()` equals the NEAR account encoded in `deposit_msg` (the deposit owner) before accepting a caller-supplied `refund_address`. Privileged roles (DAO, Operator, RefundOperator) may be exempted to preserve operational flexibility.

```rust
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.account_id,
        "Only the deposit owner may specify a refund_address"
    );
}
```

### Proof of Concept
1. Alice deposits 1 BTC to the bridge using a standard `deposit_msg` (no `refund_address`). The relayer never calls `verify_deposit`.
2. Bob (attacker) observes Alice's deposit transaction on-chain and reconstructs her `deposit_msg`.
3. Bob calls `request_refund(alice_deposit_msg, bob_btc_address, alice_tx_bytes, vout, proof, None)` with the required NEAR storage deposit.
4. The light-client proof passes; the `RefundRequest` is stored with `refund_address = bob_btc_address`.
5. The DAO does not reject within `unsafe_refund_timelock_sec`.
6. Bob calls `execute_refund(utxo_storage_key, None)`.
7. The bridge builds and MPC-signs a Bitcoin transaction paying Bob's address.
8. Alice's 1 BTC is permanently lost to Bob. [5](#0-4) [1](#0-0)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L132-184)
```rust
impl Contract {
    /// Submit a refund request. Verifies the BTC transaction via Light Client first.
    /// If `deposit_msg.refund_address` is set, it must match the provided `refund_address`.
    /// If `deposit_msg.refund_address` is None, the provided `refund_address` is used.
    #[allow(clippy::too_many_arguments)]
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
