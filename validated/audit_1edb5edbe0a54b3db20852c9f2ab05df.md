### Title
Missing BTC Address Validation in `request_refund` Allows Attacker to Temporarily Lock User Funds - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
The `request_refund` flow stores a caller-supplied `refund_address` string into `RefundRequest` without validating it as a syntactically correct BTC address for the configured chain. BTC address parsing is deferred until `execute_refund` calls `build_refund_output`, where an invalid address causes a panic and state revert. Because only one refund request may exist per UTXO, the stuck request blocks any subsequent valid `request_refund` call for the same UTXO, temporarily locking the user's BTC until a DAO/Operator manually rejects the bad request.

### Finding Description
`request_refund_callback` accepts any arbitrary string as `refund_address` and persists it directly into `RefundRequest` with no BTC address parsing:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 564-578
let refund_request = RefundRequest {
    deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
    utxo_storage_key: utxo_storage_key.clone(),
    tx_bytes,
    vout,
    amount,
    refund_address,          // ← stored verbatim, never parsed
    gas_fee: resolved_gas_fee,
    created_at_sec: nano_to_sec(env::block_timestamp()),
    executed: false,
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [1](#0-0) 

The only guard in `internal_request_refund` is a string-equality check that fires only when `deposit_msg.refund_address` is already set:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case for standard deposits), any string passes through unchecked.

BTC address validation is deferred to `build_refund_output`, called only during `execute_refund`:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 296-297
let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
    .expect("Invalid refund address");
``` [3](#0-2) 

A NEAR `panic!` / `.expect()` failure reverts all state changes in the call, so the `RefundRequest` remains in storage with `executed: false`. The duplicate-request guard then blocks any subsequent `request_refund` for the same UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

### Impact Explanation
The user's BTC UTXO is effectively frozen: `execute_refund` panics on every invocation, no new refund request can be submitted, and the UTXO cannot be reclaimed until a DAO or Operator calls `reject_refund`. This matches the allowed impact class **"attacker-triggered temporary locking of bridged funds"** (Medium).

### Likelihood Explanation
`request_refund` is a public, permissionless entry point (no role guard beyond `#[pause]`). An attacker who observes a pending deposit UTXO on-chain — and reconstructs the `deposit_msg` from the NEAR `verify_deposit` call data — can front-run or race the legitimate refund request. The only cost is the NEAR storage deposit required by `required_balance_for_request_refund`. Deposits where `deposit_msg.refund_address` is `None` (i.e., the majority of standard deposits) are fully exposed.

### Recommendation
Validate `refund_address` as a parseable BTC address for the configured chain at the point of storage, either in `internal_request_refund` (before the async Light Client call) or at the start of `request_refund_callback`, mirroring the pattern already used in `build_refund_output`:

```rust
// Validate early, before storing
crate::network::Address::parse(&refund_address, self.internal_config().chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This ensures that any invalid address is rejected immediately and the UTXO is never blocked by an unexecutable refund request.

### Proof of Concept
1. User deposits BTC with `deposit_msg.refund_address = None` (standard deposit, never finalized via `verify_deposit`).
2. Attacker calls `request_refund` with `refund_address = "not_a_valid_btc_address"`, attaching the required NEAR storage deposit.
3. Light Client verification succeeds; `request_refund_callback` stores the `RefundRequest` with the invalid address.
4. Anyone calls `execute_refund` → `build_refund_output` → `Address::parse` panics → state reverts; `RefundRequest` remains with `executed: false`.
5. User attempts `request_refund` with a valid address → rejected: `"Refund request already exists for this UTXO"`.
6. User's BTC is locked until DAO/Operator calls `reject_refund`, then the user must re-submit and wait out the full `unsafe_refund_timelock_sec` (default 14 days) again.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
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
