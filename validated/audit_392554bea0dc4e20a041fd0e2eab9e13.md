### Title
Unauthenticated `request_refund` Allows Attacker to Inject Arbitrary `refund_address`, Locking or Redirecting Victim's BTC Refund - (File: contracts/satoshi-bridge/src/api/bridge.rs, contracts/satoshi-bridge/src/refund.rs)

---

### Summary
`request_refund` carries no caller-identity check. Any NEAR account can submit a refund request for any unfinalized deposit UTXO and supply an arbitrary `refund_address`. Because only one request can exist per UTXO, the legitimate depositor is blocked from filing their own request, and the attacker-supplied address is the one used when `execute_refund` fires after the timelock.

---

### Finding Description

`request_refund` is a public, permissionless entry point:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs:510-535
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,   // ← caller-supplied, no identity check
    tx_bytes: Base64VecU8,
    vout: usize,
    proof: TxInclusionProof,
    gas_fee: Option<U128>,
) -> Promise {
    if gas_fee.is_some() { /* DAO/Operator only */ }
    self.internal_request_refund(deposit_msg, refund_address, ...)
}
```

In `request_refund_callback` the bridge verifies that the transaction output matches the deposit address derived from `deposit_msg`, but it never checks that the caller is the depositor (`deposit_msg.recipient_id`) or that `refund_address` belongs to the depositor:

```rust
// contracts/satoshi-bridge/src/refund.rs:564-574
let refund_request = RefundRequest {
    deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
    utxo_storage_key: utxo_storage_key.clone(),
    tx_bytes,
    vout,
    amount,
    refund_address,          // ← stored verbatim, no ownership binding
    gas_fee: resolved_gas_fee,
    created_at_sec: nano_to_sec(env::block_timestamp()),
    executed: false,
};
```

A duplicate-request guard prevents a second request for the same UTXO:

```rust
// contracts/satoshi-bridge/src/refund.rs:544-547
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

So whoever submits first owns the `refund_address` slot. The legitimate depositor has no way to evict the attacker's request: `reject_refund` is restricted to DAO/Operator or to the case where the UTXO was already finalized via `verify_deposit`:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs:564-567
require!(
    is_privileged || is_already_deposited,
    "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
);
```

After `unsafe_refund_timelock_sec` elapses, `execute_refund` is also permissionless — anyone can call it, and the BTC is sent to the stored `refund_address`.

The `deposit_msg` needed to mount the attack is public: `get_user_deposit_address` emits it as a NEAR event (`LogDepositAddress`) every time a user generates a deposit address, so an attacker can harvest it by watching the NEAR chain.

---

### Impact Explanation

**Guaranteed Medium impact (temporary locking):** As soon as the attacker's request lands, the legitimate depositor is blocked from filing their own refund request. Their BTC is locked in limbo for at least `unsafe_refund_timelock_sec`.

**Conditional Critical impact (theft):** If the DAO/Operator does not reject the attacker's request before `unsafe_refund_timelock_sec` expires, the attacker calls `execute_refund` and the bridge's MPC pipeline constructs and signs a Bitcoin transaction paying the attacker's address. The depositor loses 100% of the stuck BTC.

---

### Likelihood Explanation

- `deposit_msg` is public via the `LogDepositAddress` NEAR event emitted by `get_user_deposit_address`.
- The BTC transaction and Merkle proof are public on the Bitcoin blockchain.
- The attacker only needs to attach a small NEAR storage deposit (`required_balance_for_request_refund`) to submit the request.
- Unfinalized deposits (relayer outage, user error, network congestion) are a normal operational occurrence, giving the attacker a recurring attack surface.
- The attacker does not need to race the legitimate user; they only need to submit before the legitimate user thinks to file a refund, which may be days after the deposit.

---

### Recommendation

Bind the `refund_address` to the depositor's identity at request time. Concretely:

1. **Require the caller to be `deposit_msg.recipient_id`** (the NEAR account that was supposed to receive nBTC) when `deposit_msg.refund_address` is `None`. Only that account should be allowed to supply an arbitrary BTC refund address.
2. Alternatively, **require `deposit_msg.refund_address` to be set** (non-`None`) before a permissionless `request_refund` is accepted; if it is `None`, restrict the call to DAO/Operator or to the `recipient_id`.
3. Allow the `recipient_id` (or anyone they authorize) to call `reject_refund` on their own UTXO, so they are not entirely dependent on DAO/Operator vigilance.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The bridge emits `LogDepositAddress` containing the full `deposit_msg`.
2. Alice sends 1 BTC to the derived address. The relayer fails to call `verify_deposit` (e.g., outage).
3. Attacker Bob monitors NEAR events, sees Alice's `deposit_msg` and the corresponding Bitcoin UTXO.
4. Bob calls `request_refund(deposit_msg=Alice's, refund_address="bob_btc_addr", tx_bytes=..., vout=0, proof=...)` with the required NEAR storage deposit.
5. `request_refund_callback` verifies the Merkle proof and stores `RefundRequest { refund_address: "bob_btc_addr", ... }`.
6. Alice tries to call `request_refund` — it reverts with "Refund request already exists for this UTXO".
7. Alice tries to call `reject_refund` — it reverts with "Only DAO/Operator can reject".
8. If DAO/Operator does not intervene before `unsafe_refund_timelock_sec` elapses, Bob calls `execute_refund("alice_utxo_key")`. The bridge builds and MPC-signs a Bitcoin transaction paying Bob's address. Alice's 1 BTC is gone.