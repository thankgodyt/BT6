### Title
Unverified `refund_address` When `deposit_msg.refund_address` Is `None` Enables Attacker-Controlled BTC Redirection - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`request_refund_callback` verifies the deposit proof (script_pubkey match) but performs **no validation of the `refund_address` parameter** when `deposit_msg.refund_address` is `None`. Any unprivileged NEAR account can call `request_refund` with a valid deposit proof for another user's UTXO and supply an attacker-controlled BTC address as the refund destination. Once stored, the legitimate depositor is locked out from submitting their own refund request for the same UTXO.

### Finding Description

In `internal_request_refund` (`contracts/satoshi-bridge/src/refund.rs`, lines 154–158), the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

When `deposit_msg.refund_address` is `None`, this block is skipped entirely. The `refund_address` argument is passed through to `request_refund_callback` and stored verbatim in the `RefundRequest` without any check.

In `request_refund_callback` (lines 496–581), the callback verifies only that the transaction output's `script_pubkey` matches the deposit address derived from `deposit_msg`:

```rust
require!(
    deposit_script_pubkey == output.script_pubkey,
    "Output script_pubkey does not match deposit address"
);
```

The `refund_address` field is never validated against the depositor's identity, the `deposit_msg.recipient_id`, or any other on-chain anchor. It is stored directly:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-supplied, never verified
    ...
};
```

Once stored, a duplicate request for the same UTXO is rejected:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

This means the first caller wins. If the attacker calls `request_refund` before the legitimate depositor, the depositor is permanently locked out from submitting their own refund request for that UTXO.

The `execute_refund` path in `bitcoin_utils/refund.rs` (lines 18–44) then builds the refund PSBT directly from `refund_request.refund_address` with no further validation:

```rust
let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
```

The MPC network signs this PSBT and the BTC is sent to the attacker's address.

The only protection is `unsafe_refund_timelock_sec` (14 days by default, `resolve_execute_refund_timelock` lines 201–228) plus DAO/Operator monitoring to reject suspicious requests. This is a governance-dependent safety mechanism, not a cryptographic guarantee.

### Impact Explanation

If DAO/Operator fails to reject the attacker's request within `unsafe_refund_timelock_sec`, the attacker executes the refund and receives the depositor's BTC (deposit amount minus gas fee). The legitimate depositor loses their funds permanently and cannot recover them through the bridge's refund mechanism (their own `request_refund` call is blocked by the duplicate check). This constitutes a significant loss of user funds.

### Likelihood Explanation

The attack is reachable by any unprivileged NEAR account. `request_refund` is `#[payable]` with no caller restriction beyond an attached storage deposit (anti-spam fee). Tests confirm regular user accounts (e.g., "alice", "bob") can call it. The attacker only needs to:
1. Observe a BTC deposit transaction on-chain where `deposit_msg.refund_address` is `None`.
2. Call `request_refund` with the correct `deposit_msg` (publicly derivable from the deposit address) and an attacker-controlled BTC address.
3. Wait for `unsafe_refund_timelock_sec` to elapse without DAO/Operator rejection.

Deposits with `refund_address: None` are a documented and supported use case. The 14-day window is a meaningful mitigation but is not a cryptographic guarantee — it depends entirely on operational monitoring.

### Recommendation

When `deposit_msg.refund_address` is `None`, bind the `refund_address` to the caller's identity or to the `deposit_msg.recipient_id`. For example:
- Require the caller to be the NEAR account identified by `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`.
- Alternatively, require `deposit_msg.refund_address` to always be set (remove the `None` path), forcing users to pre-authorize a BTC refund address at deposit time.
- At minimum, store the NEAR account that submitted the refund request and restrict `execute_refund` to that account or privileged roles.

### Proof of Concept

1. Alice deposits BTC with `deposit_msg = { recipient_id: "alice.near", refund_address: None }`. The deposit address is derived from this message.
2. The relayer fails to call `verify_deposit` (relayer outage, etc.).
3. Attacker observes Alice's BTC transaction on-chain and reconstructs `deposit_msg` from the deposit address derivation.
4. Attacker calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "alice.near", refund_address: None },
     refund_address = "attacker_btc_address",
     tx_bytes = <Alice's tx>,
     vout = 0,
     proof = <valid inclusion proof>,
     gas_fee = None
   )
   ```
5. `internal_request_refund`: `deposit_msg.refund_address` is `None` → no check on `refund_address`. Proceeds.
6. `request_refund_callback`: `deposit_script_pubkey == output.script_pubkey` ✓ (deposit_msg is correct). Stores `RefundRequest { refund_address: "attacker_btc_address", ... }`.
7. Alice calls `request_refund` with her own BTC address → panics: `"Refund request already exists for this UTXO"`. Alice is locked out.
8. After 14 days (if DAO/Operator does not call `reject_refund`), attacker calls `execute_refund`.
9. `build_refund_output` builds a PSBT paying `"attacker_btc_address"`. MPC signs it.
10. Attacker broadcasts the transaction and receives Alice's BTC.