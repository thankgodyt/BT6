### Title
Uncommitted `refund_address` Allows Anyone to Redirect BTC Refund to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

When a user deposits BTC without embedding a `refund_address` inside `DepositMsg`, the refund destination is not committed to in the deposit address derivation. Because `request_refund` is publicly callable and only enforces address consistency when `deposit_msg.refund_address` is `Some(...)`, any attacker who learns the `deposit_msg` can submit a competing refund request with an arbitrary `refund_address`, stealing the deposited BTC.

### Finding Description

The deposit address is derived by hashing the JSON serialization of `DepositMsg`:

```rust
// deposit_msg.rs
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
``` [1](#0-0) 

All optional fields in `DepositMsg` carry `#[serde(skip_serializing_if = "Option::is_none")]`:

```rust
pub struct DepositMsg {
    pub recipient_id: AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_deposit: Option<SafeDepositMsg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
``` [2](#0-1) 

When `refund_address` is `None` it is omitted from the JSON, so the deposit address is identical regardless of what refund destination the depositor intended. The `request_refund` public entry point only validates the address when the field is `Some`:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [3](#0-2) 

`request_refund` carries no `#[trusted_relayer]` guard on the function itself (only `#[payable]` and `#[pause]`), making it callable by any NEAR account:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
``` [4](#0-3) 

Refund requests are keyed by `utxo_storage_key` (`{tx_id}@{vout}`) and only one request per UTXO is allowed:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [5](#0-4) 

An attacker who submits first wins the slot; the legitimate user's subsequent call reverts.

### Impact Explanation

An attacker who front-runs (or races) the victim's `request_refund` call with the same `deposit_msg` but their own `refund_address` will:

1. Lock the victim out of the refund slot (only one request per UTXO).
2. After `unsafe_refund_timelock_sec` elapses without DAO/Operator intervention, call `execute_refund` and receive the victim's BTC at the attacker-controlled address.

This constitutes direct theft of user BTC funds. The DAO/Operator can reject the request during the extended timelock, but this is an operational safeguard, not a protocol-level guarantee. If operators are slow or unavailable, the BTC is lost.

**Impact: Medium** — attacker-triggered redirection of bridged funds requiring operator intervention to prevent; escalates to Critical if the operator does not act within `unsafe_refund_timelock_sec`.

### Likelihood Explanation

- `deposit_msg` values are publicly emitted via `Event::LogDepositAddress` at address-generation time, so the attacker does not need to reverse any hash.
- The BTC transaction bytes and Merkle proof are publicly readable from the Bitcoin blockchain.
- `request_refund` is callable by any NEAR account with a small NEAR storage deposit.
- The attacker only needs to submit their transaction before the victim's is finalized — straightforward on NEAR where transaction ordering within a block is observable.

### Recommendation

Require that `refund_address` is always embedded inside `DepositMsg` (making it part of the deposit address derivation), or bind the refund address to the caller's NEAR account ID so it cannot be supplied by a third party. At minimum, reject `request_refund` calls where `deposit_msg.refund_address` is `None` and the caller is not the original `recipient_id`:

```rust
// If no refund_address is pre-committed, only the recipient may request a refund
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.recipient_id,
        "Only the recipient may request a refund without a pre-committed refund_address"
    );
}
```

The cleanest fix (analogous to the original report's recommendation) is to include `refund_address` in `get_deposit_path` unconditionally, committing the refund destination at deposit time.

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `DepositMsg { recipient_id: "alice.near", refund_address: None }`. The bridge emits `LogDepositAddress` with the full `deposit_msg`.
2. Alice sends 1 BTC to the derived address. The deposit is never finalized (e.g., wrong metadata).
3. Attacker observes the `LogDepositAddress` event and the BTC transaction on-chain.
4. Attacker calls `request_refund(deposit_msg={"recipient_id":"alice.near"}, refund_address="attacker_btc_addr", tx_bytes=..., vout=0, proof=...)` with a small NEAR storage deposit.
5. `request_refund_callback` verifies the deposit address matches (it does — `deposit_msg` is identical), stores the request with `refund_address = "attacker_btc_addr"`.
6. Alice calls `request_refund` with her own `refund_address` — it reverts: `"Refund request already exists for this UTXO"`.
7. After `unsafe_refund_timelock_sec` passes without DAO/Operator rejection, attacker calls `execute_refund`, and the MPC pipeline sends 1 BTC to `"attacker_btc_addr"`. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L10-28)
```rust
#[near(serializers = [json])]
#[derive(Clone)]
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-518)
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
```
