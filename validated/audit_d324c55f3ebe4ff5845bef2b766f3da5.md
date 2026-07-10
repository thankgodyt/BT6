### Title
Unconstrained `refund_address` in `request_refund` Enables Front-Running to Redirect User BTC Refunds - (File: contracts/satoshi-bridge/src/api/bridge.rs, contracts/satoshi-bridge/src/refund.rs)

---

### Summary

When a user calls `request_refund` without having pre-committed a `refund_address` inside their `deposit_msg` (i.e., `deposit_msg.refund_address` is `None`), the `refund_address` parameter is entirely unconstrained by any cryptographic commitment. Any observer can front-run the user's `request_refund` call with the same proof but a different `refund_address`, locking in the attacker's BTC address as the refund destination. Because only one refund request is allowed per UTXO, the user's subsequent call is rejected, and after the timelock elapses the BTC is sent to the attacker.

---

### Finding Description

The `request_refund` function accepts a `refund_address` parameter that is only validated against `deposit_msg.refund_address` when that field is `Some`:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None`, the `refund_address` argument is accepted from whoever calls the function first, with no binding to the depositor's identity or any on-chain commitment. The deposit address is derived solely from the hash of `deposit_msg`:

```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
``` [2](#0-1) 

Since `refund_address` is not part of `deposit_msg`, it is not part of the cryptographic path derivation. The `request_refund` function itself has no caller restriction — it carries only `#[payable]` and `#[pause]`, not `#[trusted_relayer]`:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
``` [3](#0-2) 

The callback enforces a first-one-wins uniqueness constraint per UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

After the `unsafe_refund_timelock_sec` (default 14 days) elapses, `execute_refund` is also callable by anyone with no caller restriction, completing the redirect:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
``` [5](#0-4) 

---

### Impact Explanation

An attacker who successfully front-runs `request_refund` with their own `refund_address` causes the bridge's MPC signing pipeline to construct and sign a Bitcoin transaction paying the attacker's address. Once `verify_refund_finalize` confirms the on-chain transaction, the user's deposited BTC is permanently transferred to the attacker. This constitutes a direct, complete theft of user funds — a Critical impact under the allowed scope (significant loss or theft of user funds).

---

### Likelihood Explanation

The attack requires:
1. Monitoring the NEAR transaction pool for `request_refund` calls — straightforward since NEAR transactions are public.
2. Resubmitting the same `deposit_msg`, `tx_bytes`, `vout`, and `proof` with a different `refund_address` — all of these are public inputs visible in the original transaction.
3. Paying a small NEAR storage deposit (`required_balance_for_request_refund`).
4. Waiting 14 days (`unsafe_refund_timelock_sec`) before calling `execute_refund`.

The 14-day timelock gives DAO/Operator a window to call `reject_refund`, but this is an operator-dependent mitigation, not a protocol-level fix. If the DAO is unavailable, slow to respond, or simply does not notice the malicious request among legitimate ones, the attack succeeds. The vulnerability is reachable by any unprivileged NEAR account.

---

### Recommendation

Require that `deposit_msg.refund_address` is always `Some` and matches the provided `refund_address`, eliminating the unconstrained path entirely. Alternatively, restrict `request_refund` so that only `env::predecessor_account_id()` matching the `deposit_msg.recipient_id` (the depositor) can submit a refund request when no refund address was pre-committed. This mirrors the ZNS fix: bind the sensitive parameter to the rightful owner's identity before accepting it.

---

### Proof of Concept

1. Alice deposits BTC with `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The deposit address is derived from the hash of this message.
2. The relayer never calls `verify_deposit`, so Alice's BTC sits unfinalized.
3. Alice calls `request_refund(deposit_msg, refund_address="alice_btc_addr", tx_bytes, vout, proof, None)`.
4. Bob observes Alice's pending NEAR transaction. Bob submits `request_refund(deposit_msg, refund_address="bob_btc_addr", tx_bytes, vout, proof, None)` with higher gas, landing first.
5. `request_refund_callback` verifies the Merkle proof (valid), checks `deposit_msg.refund_address` is `None` (no constraint), and stores `RefundRequest { refund_address: "bob_btc_addr", ... }`.
6. Alice's call arrives and fails: `"Refund request already exists for this UTXO"`.
7. After 14 days, Bob (or anyone) calls `execute_refund("txid@vout", None)`. The bridge builds a PSBT paying `"bob_btc_addr"` and requests an MPC signature.
8. The signed transaction is broadcast; Alice's BTC is sent to Bob. [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
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
