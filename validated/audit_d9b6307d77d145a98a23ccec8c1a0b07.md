### Title
Arbitrary `refund_address` Accepted When `deposit_msg.refund_address` Is `None`, Enabling BTC Theft via Front-Running - (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `internal_request_refund` function accepts a caller-supplied `refund_address` without any binding to the original depositor when the embedded `deposit_msg.refund_address` field is `None`. An attacker who learns the victim's `deposit_msg` (e.g., from a failed or pending `verify_deposit` NEAR transaction) can race to register a refund request pointing to their own Bitcoin address. After the `unsafe_refund_timelock_sec` elapses — and only if the DAO/Operator fails to reject it — the attacker can execute the refund and receive the victim's BTC.

---

### Finding Description

In `contracts/satoshi-bridge/src/refund.rs`, `internal_request_refund` enforces the `refund_address` only when the `deposit_msg` already contains one:

```rust
// refund.rs L154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

When `deposit_msg.refund_address` is `None`, the check is skipped entirely and any caller-supplied `refund_address` is stored verbatim in the `RefundRequest`. There is no verification that the caller is the original depositor or that the `refund_address` belongs to them.

The protocol acknowledges this risk and applies a longer timelock for this case:

```rust
// refund.rs L216-227
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
```

However, this is a purely operational mitigation — it relies entirely on the DAO/Operator noticing and rejecting the malicious request before the timelock expires. There is no on-chain enforcement that the `refund_address` belongs to the depositor.

The `deposit_msg` is not secret: it is submitted on-chain by relayers as part of `verify_deposit` calls, and it is also submitted by the user themselves in `request_refund`. An attacker monitoring NEAR transactions can extract the `deposit_msg` from a failed deposit attempt or from the user's own pending `request_refund` call, then immediately submit their own `request_refund` with the same `deposit_msg` but a different `refund_address`. Because the code enforces uniqueness per UTXO:

```rust
// refund.rs L544-547
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

whichever request lands first wins. The victim's subsequent attempt is rejected.

---

### Impact Explanation

If the DAO/Operator does not reject the malicious refund request within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund`, which builds a signed Bitcoin transaction paying the attacker's address. Once the refund transaction is broadcast and confirmed, the victim's BTC is permanently transferred to the attacker. This is a direct, irreversible loss of user funds.

This maps to: **Medium — Bypass of bridge limits or policies, or attacker-triggered temporary locking of bridged funds** (and escalates to Critical if the DAO fails to act, resulting in permanent loss).

---

### Likelihood Explanation

- Users who do not include `refund_address` in their `deposit_msg` are vulnerable. This is a common case since `refund_address` is optional.
- The `deposit_msg` is observable on-chain from relayer `verify_deposit` submissions or from the user's own `request_refund` transaction.
- The attack requires no special privileges, no flash loans, and no complex setup — only monitoring NEAR transactions and submitting a competing `request_refund`.
- The only defense is the DAO/Operator manually rejecting the request before `unsafe_refund_timelock_sec` expires. If the DAO is slow, offline, or does not notice, the attack succeeds.

---

### Recommendation

Bind the `refund_address` to the depositor at the time of deposit, not at the time of refund request. Concretely:

1. **Require `deposit_msg.refund_address` to always be set** — reject deposits whose `deposit_msg` omits it. This ensures the refund destination is committed to in the Bitcoin transaction itself (via the deposit address derivation), making it immutable.
2. Alternatively, if caller-supplied `refund_address` must be supported, require the caller to prove ownership (e.g., sign a message with the corresponding Bitcoin private key), or restrict `request_refund` to a whitelisted relayer set that is trusted to supply the correct address.

---

### Proof of Concept

1. Alice sends BTC to a deposit address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: null }`.
2. The relayer submits `verify_deposit(deposit_msg, ...)` on NEAR; the call fails (e.g., insufficient confirmations). The `deposit_msg` is now visible in NEAR transaction history.
3. Alice prepares to call `request_refund(deposit_msg, "alice_btc_address", tx_bytes, vout, proof, gas_fee)`.
4. Attacker observes Alice's pending transaction, extracts `deposit_msg`, and submits `request_refund(deposit_msg, "attacker_btc_address", tx_bytes, vout, proof, gas_fee)` first.
5. Attacker's request is stored; Alice's subsequent call reverts with `"Refund request already exists for this UTXO"`.
6. After `unsafe_refund_timelock_sec` elapses (and assuming the DAO does not reject), attacker calls `execute_refund(utxo_storage_key)`.
7. The bridge builds and signs a Bitcoin transaction paying `"attacker_btc_address"`.
8. Attacker broadcasts the transaction; Alice's BTC is permanently lost. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L10-28)
```rust
#[near(serializers = [json])]
#[derive(Clone)]
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
