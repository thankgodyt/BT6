I have all the code needed to make a definitive assessment. Let me trace the exact path.

**Step 1: `request_refund` is open to any caller**

The function at line 510 has no `#[trusted_relayer]` on the function itself (only on the impl block for grouping), and no caller identity check. The test `test_refund_spoofed_refund_address` confirms "bob" (unprivileged) can call it — the failure there is a content check, not an ACL check.

**Step 2: The `refund_address` guard only fires when `deposit_msg.refund_address` is `Some`** [1](#0-0) 

When `deposit_msg.refund_address` is `None`, the `if let Some(...)` branch is skipped entirely. Any `refund_address` string the caller supplies is accepted.

**Step 3: The callback only verifies the BTC output matches the deposit address derived from `deposit_msg`** [2](#0-1) 

The attacker uses the victim's exact `deposit_msg` (with `refund_address: None`), so the derived deposit address matches the real BTC output. The callback passes.

**Step 4: The stored `RefundRequest` carries the attacker-supplied `refund_address`** [3](#0-2) 

**Step 5: `unsafe_refund_timelock_sec` (14 days) is applied — not the shorter `refund_timelock_sec`** [4](#0-3) 

Because `deposit_msg.refund_address` is `None`, the longer timelock branch is taken. The default is 14 days. [5](#0-4) 

**Step 6: After the timelock, `execute_refund` → `finalize_refund_with_psbt` marks the UTXO in `verified_deposit_utxo`** [6](#0-5) 

**Step 7: Victim's `verify_deposit` is now permanently blocked** [7](#0-6) 

The `verified_deposit_utxo` set blocks any subsequent `verify_deposit` for that UTXO. The BTC is sent to the attacker's address via the MPC signing pipeline.

---

### Title
Unprivileged attacker can hijack any `refund_address: None` deposit refund, redirect BTC to attacker-controlled address, and permanently block victim's `verify_deposit` — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
When a victim's `DepositMsg` has `refund_address: None`, any unprivileged NEAR account can call `request_refund` with the victim's exact `deposit_msg` and an attacker-controlled BTC address. After the 14-day `unsafe_refund_timelock_sec`, the attacker calls `execute_refund`, which marks the UTXO in `verified_deposit_utxo` and initiates an MPC-signed BTC transaction to the attacker's address. The victim's `verify_deposit` is permanently blocked.

### Finding Description
`internal_request_refund` in `refund.rs` enforces `refund_address == deposit_msg.refund_address` only when `deposit_msg.refund_address` is `Some`:

```rust
// refund.rs:154-159
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

When `deposit_msg.refund_address` is `None`, the guard is entirely skipped. The `request_refund_callback` only verifies that the BTC output's `script_pubkey` matches the deposit address derived from `deposit_msg` — it does not verify the caller's identity or that the supplied `refund_address` belongs to the depositor. The attacker uses the victim's real `deposit_msg` (derivable from the public deposit address), so the BTC output check passes. The `RefundRequest` is stored with the attacker's `refund_address`.

`resolve_execute_refund_timelock` applies `unsafe_refund_timelock_sec` (14 days) for the `None` case, giving DAO/Operator a window to call `reject_refund`. However, if no rejection occurs within 14 days, `execute_refund` → `finalize_refund_with_psbt` inserts the UTXO into `verified_deposit_utxo` and queues an MPC-signed BTC transaction paying the attacker's address. The victim's `verify_deposit` then permanently fails with "UTXO already verified via deposit, cannot refund".

### Impact Explanation
- **BTC theft**: The victim's deposited BTC is sent to the attacker's BTC address via the MPC signing pipeline.
- **Permanent deposit block**: `verified_deposit_utxo` membership blocks `verify_deposit` forever for that UTXO, even if the refund BTC transaction is never broadcast or confirmed.
- The victim loses their BTC and cannot receive nBTC.

### Likelihood Explanation
- The attack requires no privilege — only a NEAR account with enough NEAR for the storage deposit.
- The victim's `deposit_msg` is fully derivable from the public deposit address (it is the preimage of the path hash).
- The 14-day window is a partial mitigation but depends entirely on active DAO/Operator monitoring. A single missed alert or a coordinated batch of such requests could exhaust monitoring capacity.
- Deposits with `refund_address: None` are a documented, supported use case (e.g., users who do not have a BTC address at deposit time).

### Recommendation
1. **Require caller authorization**: When `deposit_msg.refund_address` is `None`, require `env::predecessor_account_id() == deposit_msg.recipient_id` (or a DAO/Operator role) to submit `request_refund`. This ensures only the intended recipient can initiate a refund for their own deposit.
2. **Alternatively**: Require `deposit_msg.refund_address` to always be `Some` — force users to pre-commit a BTC refund address at deposit time, eliminating the open-`refund_address` path entirely.
3. **Defense-in-depth**: Even with fix (1), retain the `unsafe_refund_timelock_sec` for DAO oversight.

### Proof of Concept
State test with two accounts:

```
// Setup: victim deposits with refund_address: None
let victim_deposit_msg = DepositMsg { recipient_id: "victim.near", refund_address: None, ... };
let deposit_address = bridge.get_user_deposit_address(victim_deposit_msg.clone());
// victim sends BTC to deposit_address (tx_bytes, vout)

// Attacker submits refund request with attacker's BTC address
attacker.call("request_refund")
    .args(victim_deposit_msg, "attacker_btc_address", tx_bytes, vout, proof)
    .deposit(required_storage)
    .call();
// → succeeds, RefundRequest stored with refund_address = "attacker_btc_address"

// Fast-forward 14 days
fast_forward(14 * 24 * 3600 / block_time);

// Attacker executes refund
attacker.call("execute_refund").args(utxo_storage_key).call();
// → verified_deposit_utxo now contains the UTXO key
// → BTCPendingInfo created, MPC signing queued to "attacker_btc_address"

// Victim's verify_deposit now fails
relayer.call("verify_deposit_v2")
    .args(victim_deposit_msg, tx_bytes, vout, proof)
    .call();
// → panics: "UTXO already verified via deposit, cannot refund"
// (or "Already deposit utxo" in the deposit callback)

assert!(victim_nbtc_balance == 0);  // victim receives nothing
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

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L516-525)
```rust
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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
