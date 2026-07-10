### Title
Any Caller Can Redirect a Stuck BTC Deposit Refund to an Arbitrary Address via Unguarded `request_refund` — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary
The `request_refund` function is publicly callable by any NEAR account. When a deposit's `deposit_msg.refund_address` is `None`, there is no check that the caller is the legitimate owner of the deposit (e.g., the `recipient_id`). An attacker can submit a refund request for a victim's stuck deposit UTXO with the attacker's own BTC address as `refund_address`, blocking the victim's own request and — if the DAO fails to reject within `unsafe_refund_timelock_sec` — causing the bridge's MPC to sign a Bitcoin transaction that sends the victim's BTC to the attacker.

---

### Finding Description

In `internal_request_refund`, the only validation of `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

This guard is entirely skipped when `deposit_msg.refund_address` is `None`. In that case, the caller may supply any BTC address as `refund_address` and the contract stores it verbatim.

The callback verifies only that the deposit output script matches the address derived from `deposit_msg` — it does not verify the caller's

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
