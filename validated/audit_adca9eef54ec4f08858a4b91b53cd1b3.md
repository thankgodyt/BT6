### Title
Missing Caller-to-Recipient Validation in `request_refund` Allows Attacker to Redirect Victim's BTC Refund — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`internal_request_refund` accepts a caller-supplied `deposit_msg` (which embeds the intended NEAR `recipient_id`) and a caller-supplied `refund_address` (the BTC destination), but never verifies that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`. When `deposit_msg.refund_address` is `None`, any account that knows the victim's `deposit_msg` can submit a refund request pointing to an attacker-controlled BTC address, redirecting the victim's BTC to the attacker.

---

### Finding Description

In `internal_request_refund`, the only cross-validation performed between `deposit_msg` and `refund_address` is the optional check at lines 154–158:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

This check is only active when the depositor pre-committed a `refund_address` inside the `deposit_msg`. When `deposit_msg.refund_address` is `None` — the common case for users who did not pre-specify a BTC return address — the branch is skipped entirely, and the caller's `refund_address` is accepted without restriction.

The `request_refund_callback` does verify that the Bitcoin transaction output script matches the deposit address derived from `deposit_msg`:

```rust
let path = get_deposit_path(&deposit_msg);
let deposit_address = self.generate_utxo_chain_address(&path);
let deposit_script_pubkey = deposit_address.script_pubkey().expect("...");
require!(
    deposit_script_pubkey == output.script_pubkey,
    "Output script_pubkey does not match deposit address"
);
``` [2](#0-1) 

This confirms the transaction is real, but it does **not** bind the caller to the `recipient_id` embedded in `deposit_msg`. There is no check of the form:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Caller is not the deposit recipient"
);
```

The `deposit_msg` struct carries `recipient_id` as a plain field: [3](#0-2) 

but this field is never compared against the caller's identity anywhere in the refund path.

---

### Impact Explanation

An attacker who obtains the victim's `deposit_msg` (with `refund_address: None`) can:

1. Call `request_refund` supplying the victim's `deposit_msg` and an attacker-controlled BTC `refund_address`.
2. The `request_refund_callback` accepts the request because the Bitcoin transaction output script correctly matches the deposit address derived from the victim's `deposit_msg`.
3. After `unsafe_refund_timelock_sec` elapses (and if the DAO does not reject), call `execute_refund`.
4. The bridge constructs and signs a Bitcoin transaction paying the victim's deposited BTC to the attacker's address.

The victim's BTC is permanently redirected to the attacker. This is a direct, irreversible theft of user funds — matching the **Critical** impact category (significant loss of user funds).

---

### Likelihood Explanation

The `deposit_msg` is not a secret. It is the input to a SHA-256 hash that produces the deposit address path: [4](#0-3) 

Users share their `deposit_msg` with the bridge frontend or relayer to initiate a deposit. A failed or unfinalized deposit (the exact scenario requiring a refund) means `verify_deposit` was never called, so the `deposit_msg` may not yet be on-chain — but it was transmitted to the relayer or frontend, making it observable to a network-level or application-level attacker. The `unsafe_refund_timelock_sec` provides a DAO intervention window, but this is an operational control, not a protocol guarantee. If the DAO misses the window, the theft is irreversible.

---

### Recommendation

Add a caller-identity check in `internal_request_refund` before accepting a caller-supplied `refund_address` when `deposit_msg.refund_address` is `None`:

```rust
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.recipient_id,
        "Only the deposit recipient can request a refund without a pre-authorized refund address"
    );
}
```

This mirrors the fix in the referenced report: verify that the account driving the operation actually corresponds to the account whose funds are at stake.

---

### Proof of Concept

1. **Victim** deposits BTC to an address derived from `deposit_msg = { recipient_id: "victim.near", refund_address: None, ... }`. The deposit is never finalized (e.g., the relayer fails).
2. **Attacker** observes the victim's `deposit_msg` (from the bridge frontend, a failed relayer transaction, or direct communication).
3. **Attacker** calls `request_refund(deposit_msg=<victim's>, refund_address=<attacker's BTC addr>, tx_bytes=<victim's deposit tx>, vout=0, proof=<valid proof>)`.
4. `internal_request_refund` checks `deposit_msg.refund_address` → it is `None` → the branch at line 154 is skipped → no caller check is performed.
5. `request_refund_callback` verifies the script_pubkey matches the deposit address derived from the victim's `deposit_msg` → passes, because the attacker used the correct `deposit_msg`.
6. A `RefundRequest` is stored with `refund_address = <attacker's BTC addr>`.
7. After `unsafe_refund_timelock_sec`, attacker calls `execute_refund`. The bridge signs and broadcasts a Bitcoin transaction paying the victim's BTC to the attacker's address.
8. Victim's BTC is permanently lost. [5](#0-4)

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
