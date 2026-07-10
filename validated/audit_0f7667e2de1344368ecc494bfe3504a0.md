### Title
Attacker Can Front-Run `request_refund` to Redirect BTC to Attacker-Controlled Address When `deposit_msg.refund_address` Is `None` - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

When a user deposits BTC using a `DepositMsg` with `refund_address: None`, the `request_refund` function performs no caller-identity check and accepts any arbitrary `refund_address` parameter. An attacker who observes the public `LogDepositAddress` event can front-run the legitimate user's `request_refund` call, registering the attacker's own BTC address as the refund destination. Because only one refund request can exist per UTXO, the legitimate user is permanently blocked from correcting the destination, and the BTC is redirected to the attacker after the timelock elapses.

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` (line 510) is a permissionless function callable by any NEAR account. Its only validation of the `refund_address` parameter is a conditional check:

```rust
// contracts/satoshi-bridge/src/refund.rs, lines 154-159
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None`, this block is skipped entirely. The caller-supplied `refund_address` is accepted unconditionally and stored verbatim in the `RefundRequest`:

```rust
// contracts/satoshi-bridge/src/refund.rs, lines 564-574
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-controlled value, no ownership check
    ...
};
``` [2](#0-1) 

The `DepositMsg` used to derive the deposit address path is fully public: `get_user_deposit_address` emits a `LogDepositAddress` event containing the complete `deposit_msg`: [3](#0-2) 

A duplicate-request guard in `request_refund_callback` (line 544) ensures only one `RefundRequest` can exist per UTXO: [4](#0-3) 

This means whichever caller wins the race owns the refund destination permanently.

The `unsafe_refund_timelock_sec` path is applied when `deposit_msg.refund_address` is `None`, giving DAO/Operator time to reject suspicious requests: [5](#0-4) 

However, this is an operational mitigation, not a protocol-level fix. If the DAO/Operator is offline, slow, or does not notice the malicious request, the attacker's `execute_refund` call succeeds after the timelock and the BTC is sent to the attacker's address.

### Impact Explanation

The BTC deposit is permanently redirected to the attacker's Bitcoin address. The legitimate depositor loses their funds with no on-chain recourse once `execute_refund` is processed. This constitutes a significant, direct theft of user funds from the bridge's controlled UTXO set.

### Likelihood Explanation

- The `deposit_msg` is fully public via the `LogDepositAddress` on-chain event.
- `request_refund` is permissionless (any NEAR account can call it, as confirmed by tests like `test_refund_no_refund_address` where "alice" calls it directly).
- The attacker only needs to submit a NEAR transaction before the victim, which is straightforward on NEAR's deterministic block production.
- The attacker must pay the storage deposit (anti-spam fee), but this is negligible compared to the BTC value at stake.
- The only defense is active DAO/Operator monitoring and timely rejection, which is an operational assumption that can fail.

### Recommendation

**Short term:** In `internal_request_refund`, when `deposit_msg.refund_address` is `None`, require that the caller (`env::predecessor_account_id()`) matches `deposit_msg.recipient_id`. This ensures only the intended NEAR recipient can register an external refund address for their own deposit.

**Long term:** Embed the refund address into the `DepositMsg` at deposit time (making it part of the key derivation), so that any refund address is cryptographically committed before the BTC transaction is sent. This eliminates the entire class of post-hoc refund-address injection.

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: "alice.near", refund_address: None, ... })`. The `LogDepositAddress` event is emitted on-chain with the full `deposit_msg`.
2. Alice sends BTC to the returned deposit address. `verify_deposit` is never called (relayer down).
3. Eve observes the `LogDepositAddress` event and reconstructs Alice's `deposit_msg`.
4. Eve calls `request_refund(alice_deposit_msg, "eve_btc_address", tx_bytes, vout, proof, None)` before Alice does.
5. `request_refund_callback` validates that the tx output script matches the deposit address derived from `alice_deposit_msg` — it does, because Eve used the correct `deposit_msg`. The request is stored with `refund_address = "eve_btc_address"`.
6. Alice attempts `request_refund` for the same UTXO and is rejected: `"Refund request already exists for this UTXO"`.
7. After `unsafe_refund_timelock_sec` elapses (and assuming DAO/Operator does not reject), Eve calls `execute_refund(utxo_storage_key)`.
8. The bridge constructs a Bitcoin transaction paying Alice's BTC deposit to Eve's address and signs it via MPC. Alice's BTC is stolen.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
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
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
    }
```
