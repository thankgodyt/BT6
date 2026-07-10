### Title
Unauthorized Refund Request Allows Any Caller to Redirect Depositor's BTC to an Arbitrary Address - (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`internal_request_refund` contains no check that the caller is the depositor (`recipient_id` in `deposit_msg`). When a deposit was made with `deposit_msg.refund_address = None` (the common case), any unprivileged NEAR account can submit a refund request for that deposit and supply an arbitrary `refund_address`. After `unsafe_refund_timelock_sec` elapses without DAO rejection, the attacker calls `execute_refund`, causing the depositor's BTC to be sent to the attacker's address and permanently blocking the depositor from ever claiming nBTC for that UTXO.

---

### Finding Description

**Root cause — no caller authorization in `internal_request_refund`:**

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

The only guard on `refund_address` is: *if the depositor pre-set a `refund_address` inside `deposit_msg`, the caller must match it*. When `deposit_msg.refund_address` is `None` — the default for ordinary deposits — the branch is skipped entirely and the caller's arbitrary `refund_address` is accepted without restriction.

There is no check anywhere in `internal_request_refund` or `request_refund_callback` that `env::predecessor_account_id()` equals `deposit_msg.recipient_id` or any other depositor-controlled identity.

**`deposit_msg` is publicly observable:**

The deposit address is derived deterministically from `deposit_msg` via `get_deposit_path`. Because the Bitcoin transaction is public, any observer can reconstruct the exact `deposit_msg` used for any deposit and pass it verbatim to `request_refund`.

**Callback stores the attacker's address:**

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 564-578
let refund_request = RefundRequest {
    ...
    refund_address,          // ← attacker-supplied
    gas_fee: resolved_gas_fee,
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
```

**Timelock is the only mitigation — not a prevention:**

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 216-227
if refund_request.deposit_msg().refund_address.is_some() {
    if is_privileged { 0 } else { config.refund_timelock_sec }
} else {
    // Refund address supplied by caller: longer timelock
    config.unsafe_refund_timelock_sec
}
```

`unsafe_refund_timelock_sec` gives the DAO a window to reject. If the DAO does not act, `execute_refund` becomes callable by anyone and the stored attacker address is used.

**Permanent blocking of legitimate deposit:**

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 377-380
self.data_mut()
    .verified_deposit_utxo
    .insert(utxo_storage_key.clone());
```

Once `finalize_refund_with_psbt` runs, the UTXO is marked verified. The legitimate depositor can never call `verify_deposit` for that UTXO again — their nBTC mint path is permanently closed.

---

### Impact Explanation

**Critical / Medium.** If the DAO fails to reject within `unsafe_refund_timelock_sec`:

- The depositor's BTC is sent to the attacker's Bitcoin address.
- The UTXO is permanently marked as verified, so the depositor can never mint nBTC for that deposit.
- The depositor suffers a total loss of the deposited BTC with no recovery path inside the bridge.

Even if the DAO rejects in time, the attacker can re-submit immediately, forcing the DAO into a continuous monitoring burden and causing the depositor's funds to remain locked until each request is individually rejected — fitting the "attacker-triggered temporary locking of bridged funds" Medium category.

---

### Likelihood Explanation

**Medium.** The attack requires no special privilege, no key material, and no on-chain front-running race — the attacker simply waits for a deposit to be confirmed on Bitcoin (publicly visible), then calls `request_refund` before the depositor calls `verify_deposit`. The `deposit_msg` is fully recoverable from the Bitcoin transaction. The only barrier is the DAO acting within `unsafe_refund_timelock_sec`; if the DAO is slow, offline, or the timelock is short, the attack succeeds.

---

### Recommendation

1. **Require the caller to be the depositor.** In `internal_request_refund` (or its public wrapper), add:
   ```rust
   require!(
       env::predecessor_account_id() == deposit_msg.recipient_id,
       "Only the depositor may request a refund"
   );
   ```
2. **Alternatively, require `deposit_msg.refund_address` to be set** before a refund request is accepted from an arbitrary caller, so that only deposits with a pre-authorized refund address can be refunded by non-depositors.

---

### Proof of Concept

1. Alice sends 1 BTC to the bridge deposit address derived from her `deposit_msg` (`recipient_id = alice.near`, `refund_address = None`).
2. The Bitcoin transaction is confirmed and publicly visible.
3. Attacker Bob reconstructs Alice's `deposit_msg` from the Bitcoin transaction data.
4. Bob calls `request_refund(deposit_msg=alice_msg, refund_address="bob_btc_addr", tx_bytes=..., vout=0, proof=...)`.
5. `internal_request_refund` verifies the proof and calls `request_refund_callback`.
6. `request_refund_callback` verifies the output script matches Alice's deposit address (it does — Bob used the correct `deposit_msg`), skips the `refund_address` check (because `deposit_msg.refund_address` is `None`), and stores `RefundRequest { refund_address: "bob_btc_addr", ... }`.
7. The DAO does not reject within `unsafe_refund_timelock_sec`.
8. Bob calls `execute_refund(utxo_storage_key)`. `finalize_refund_with_psbt` builds a PSBT paying 1 BTC (minus gas fee) to `bob_btc_addr` and marks the UTXO as verified.
9. Alice's UTXO is now permanently blocked from `verify_deposit`. Alice loses her BTC; Bob receives it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-158)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-227)
```rust
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
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
