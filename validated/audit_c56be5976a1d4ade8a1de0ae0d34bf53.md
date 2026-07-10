### Title
Permissionless `request_refund` Allows Attacker to Front-Run Any Deposit and Redirect Refund to Attacker-Controlled Bitcoin Address — (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`internal_request_refund` is callable by any unprivileged NEAR account. When a deposit's `DepositMsg` carries no pre-authorized `refund_address` (the common case), the caller may supply an arbitrary Bitcoin address. An attacker who observes a victim's deposit transaction on Bitcoin can race to register a refund request for that UTXO with the attacker's own Bitcoin address, blocking the victim from registering their own refund and — if the DAO/Operator fails to reject the request within `unsafe_refund_timelock_sec` — redirecting the victim's BTC to the attacker.

### Finding Description
`internal_request_refund` enforces no caller identity check: [1](#0-0) 

The only address-binding guard is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` — the default for ordinary deposits — the check is skipped entirely, and the caller-supplied `refund_address` is stored verbatim in the `RefundRequest`: [3](#0-2) 

A duplicate-request guard prevents a second `request_refund` for the same UTXO: [4](#0-3) 

So once the attacker's request is stored, the victim cannot overwrite it with a legitimate one.

After `unsafe_refund_timelock_sec` elapses, `execute_refund` (also reachable by any caller) builds a PSBT paying `refund_amount` to the stored `refund_address` and marks the UTXO as verified, permanently blocking a subsequent `verify_deposit`: [5](#0-4) 

### Impact Explanation
- **Immediate / guaranteed (Medium):** The attacker's front-run request occupies the UTXO slot, preventing the victim from filing their own refund request. The bridge enters a stuck state for that UTXO that requires explicit DAO/Operator intervention (`internal_reject_refund`) to clear.
- **Conditional / critical:** If the DAO does not reject the malicious request before `unsafe_refund_timelock_sec` expires, any caller can invoke `execute_refund`, which pays the victim's BTC to the attacker's Bitcoin address and marks the UTXO verified — permanently locking the victim out of both a legitimate deposit and a self-directed refund. This constitutes unauthorized release of bridge-controlled BTC funds.

### Likelihood Explanation
Bitcoin deposit transactions are public. The `DepositMsg` is embedded in the OP_RETURN output and is therefore visible to any observer. An attacker needs only: (1) a valid Merkle inclusion proof (available once the block is mined), (2) the victim's `deposit_msg` (on-chain), and (3) enough NEAR to cover the storage deposit. No privileged access is required. The attack window is the entire period between block confirmation and the victim calling `verify_deposit` or `request_refund`.

### Recommendation
Restrict `request_refund` so that only the `recipient_id` encoded in `deposit_msg` (or a DAO/Operator role) may submit a refund request for a given UTXO. Alternatively, when `deposit_msg.refund_address` is `None`, require the caller to be the `deposit_msg.recipient_id` and bind the stored `refund_address` to that caller's submission, preventing third-party substitution.

### Proof of Concept
1. Victim sends 1 BTC to the bridge deposit address. The on-chain OP_RETURN encodes `DepositMsg { recipient_id: "victim.near", refund_address: None, … }`.
2. Attacker observes the transaction, obtains the Merkle proof, and calls `request_refund(deposit_msg, refund_address="attacker_btc_addr", tx_bytes, vout, proof, gas_fee)` with a NEAR storage deposit.
3. `request_refund_callback` verifies the proof, confirms the output script matches the deposit address derived from `deposit_msg`, and stores `RefundRequest { refund_address: "attacker_btc_addr", … }` keyed by `utxo_storage_key`.
4. Victim attempts `request_refund` — rejected: "Refund request already exists for this UTXO".
5. `unsafe_refund_timelock_sec` elapses without DAO intervention.
6. Attacker calls `execute_refund(utxo_storage_key, …)`. The contract builds a PSBT paying 1 BTC (minus gas fee) to `"attacker_btc_addr"`, inserts the UTXO into `verified_deposit_utxo`, and initiates MPC signing.
7. Victim's BTC is redirected to the attacker; the victim's UTXO is permanently consumed.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L136-159)
```rust
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

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
