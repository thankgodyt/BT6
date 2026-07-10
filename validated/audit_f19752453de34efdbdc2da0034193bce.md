### Title
Front-Running `request_refund` with Attacker-Controlled `refund_address` Enables DoS and BTC Theft - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`request_refund` is publicly callable with no caller restriction. The refund request is keyed by `utxo_storage_key` (`{tx_id}@{vout}`), which does not commit to the `refund_address` parameter. When `deposit_msg.refund_address` is `None`, the `refund_address` argument is accepted without any user-controlled commitment. An attacker can front-run a legitimate `request_refund` call with the same `deposit_msg` and `tx_bytes` but a different `refund_address` pointing to their own BTC address, causing the victim's transaction to revert and potentially redirecting the refund payout to the attacker.

### Finding Description
In `internal_request_refund`, the `refund_address` is only validated against `deposit_msg.refund_address` when the latter is explicitly set:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None` (the common case for users who did not pre-commit a refund address), any `refund_address` value is accepted without restriction.

The refund request is stored under a key derived solely from the Bitcoin transaction:

```rust
let utxo_storage_key = generate_utxo_storage_key(
    tx_id,
    u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
);
``` [2](#0-1) 

This key does **not** include the `refund_address`. A duplicate insertion is then blocked:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

Attack scenario:
1. Alice sends BTC to a deposit address derived from `DepositMsg { recipient_id: alice, refund_address: None, … }`.
2. Alice calls `request_refund(deposit_msg, alice_btc_addr, tx_bytes, vout, proof, None)`.
3. Bob front-runs with `request_refund(deposit_msg, bob_btc_addr, tx_bytes, vout, proof, None)` — identical `deposit_msg` and `tx_bytes`, but `refund_address = bob_btc_addr`.
4. Bob's transaction lands first; the refund request is stored with `refund_address = bob_btc_addr`.
5. Alice's transaction reverts: "Refund request already exists for this UTXO".
6. After `unsafe_refund_timelock_sec` elapses (and if DAO/Operator does not reject), anyone calls `execute_refund`, and Alice's BTC is sent to Bob's address.

The `unsafe_refund_timelock_sec` path is taken precisely because `deposit_msg.refund_address` is `None`:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [4](#0-3) 

This longer timelock is a partial mitigation but relies entirely on active DAO/Operator monitoring and timely intervention. It does not prevent the DoS, and if the operator is unavailable or inattentive, the theft completes.

The `get_deposit_path` function correctly hashes the full `DepositMsg` to derive the BTC deposit address:

```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
``` [5](#0-4) 

The deposit address derivation is sound; the vulnerability is that the refund request identifier (`utxo_storage_key`) does not commit to the `refund_address`, allowing it to be substituted by a front-runner.

### Impact Explanation
**Minimum (guaranteed) impact — Medium:** Alice cannot complete a refund. Every time she submits `request_refund`, Bob can front-run and occupy the slot. Alice's BTC is temporarily locked in the bridge UTXO with no path to recovery until DAO/Operator rejects Bob's request, after which Bob can front-run again indefinitely.

**Maximum impact — Critical:** If DAO/Operator does not reject Bob's request within `unsafe_refund_timelock_sec`, `execute_refund` sends Alice's BTC to Bob's address. This is a direct, complete theft of user funds with no on-chain recourse.

### Likelihood Explanation
The attack requires only an unprivileged NEAR account and the ability to observe pending transactions. `request_refund` is publicly callable (no `#[trusted_relayer]` at the method level, confirmed by integration tests where regular user accounts call it directly). The attacker needs the same `deposit_msg` and `tx_bytes` as the victim, both of which are observable on-chain or in the mempool. The attack is repeatable: every time Alice retries, Bob can front-run again.

### Recommendation
1. **Commit the `refund_address` into the storage key** when `deposit_msg.refund_address` is `None`, e.g. `utxo_storage_key = "{tx_id}@{vout}@{sha256(refund_address)}"`. This ensures different `refund_address` values produce different keys, so Bob's front-run does not block Alice's slot.
2. **Alternatively, require `deposit_msg.refund_address` to always be set** (make it non-optional). Users must pre-commit their refund address in the `DepositMsg` before sending BTC, eliminating the free-parameter attack surface entirely.
3. **Alternatively, restrict `request_refund` to the `deposit_msg.recipient_id`** so only the intended recipient can initiate a refund for their own deposit.

### Proof of Concept
```
1. Alice derives deposit address from DepositMsg { recipient_id: alice.near, refund_address: None }
2. Alice sends 100_000 sat to that address (tx_id = "aabbcc...", vout = 0)
3. Alice submits: request_refund(deposit_msg, "bc1q_alice...", tx_bytes, 0, proof, None)
4. Bob observes Alice's pending call and submits first:
       request_refund(deposit_msg, "bc1q_bob...", tx_bytes, 0, proof, None)
   Bob's call succeeds; refund_requests["aabbcc...@0"] = { refund_address: "bc1q_bob..." }
5. Alice's call reverts: "Refund request already exists for this UTXO"
6. After unsafe_refund_timelock_sec passes (DAO/Operator does not intervene):
       execute_refund("aabbcc...@0", None)
   Bridge MPC-signs a BTC tx paying 100_000 sat (minus gas fee) to "bc1q_bob..."
   Alice's BTC is stolen.
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L529-532)
```rust
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```
