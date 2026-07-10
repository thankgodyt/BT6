### Title
Permissionless `request_refund` Allows Any Caller to Redirect BTC Refunds to an Attacker-Controlled Address When `deposit_msg.refund_address` Is `None` - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
When a user deposits BTC without embedding a pre-authorized `refund_address` in the `DepositMsg` (`deposit_msg.refund_address = None`), the `request_refund` entry-point is fully permissionless and accepts any caller-supplied BTC address. An attacker who observes the on-chain deposit can front-run the legitimate user's `request_refund` call and register an attacker-controlled BTC address as the refund destination. Because the contract rejects any subsequent `request_refund` for the same UTXO, the user's call fails and the refund is permanently locked to the attacker's address. After `unsafe_refund_timelock_sec` elapses (if the DAO does not reject the request), `execute_refund` — also permissionless — can be called by anyone to execute the refund to the attacker's address.

### Finding Description

`request_refund` carries no caller-identity check. Its only access guards are `#[payable]` (storage deposit) and `#[pause]`:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
) -> Promise {
``` [1](#0-0) 

Inside `internal_request_refund`, the only constraint on `refund_address` is that it must equal `deposit_msg.refund_address` **when that field is `Some`**. When it is `None`, any address is accepted without restriction:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

Once a `RefundRequest` is stored for a UTXO, any subsequent `request_refund` for the same UTXO is rejected:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

`execute_refund` is equally permissionless — no role check, no relayer check — and uses the stored `refund_address` verbatim:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
}
``` [4](#0-3) 

The stored `refund_address` is used directly to build the Bitcoin output — no re-validation against the original depositor:

```rust
vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
``` [5](#0-4) 

The `unsafe_refund_timelock_sec` path (applied when `deposit_msg.refund_address` is `None`) is intended to give the DAO time to reject suspicious requests, but this is an off-chain, manual, best-effort control — not an on-chain guarantee. [6](#0-5) 

### Impact Explanation

An attacker who successfully front-runs the user's `request_refund` call permanently redirects the entire BTC deposit (minus gas fee) to an attacker-controlled Bitcoin address. The user's own `request_refund` call will revert with "Refund request already exists for this UTXO," leaving them with no on-chain recourse. This constitutes direct, irreversible theft of user funds — matching the Critical impact class: **Significant loss or theft of user funds**.

### Likelihood Explanation

- `DepositMsg` fields (including `recipient_id`) are emitted in on-chain events (`LogDepositAddress`), making the full `deposit_msg` observable by any NEAR account.
- NEAR transaction ordering is deterministic within a block; an attacker monitoring the mempool or events can submit `request_refund` with a higher gas price to front-run the user.
- Users who do not embed `refund_address` in `DepositMsg` (the `None` path) are the target population; this is a documented and supported usage pattern.
- The DAO mitigation (`unsafe_refund_timelock_sec`) is manual and reactive; a DAO that is not actively monitoring or that is slow to respond leaves the window open.

### Recommendation

Bind the refund destination to the depositor's identity at request time. Two complementary fixes:

1. **Require caller authentication in `request_refund`**: When `deposit_msg.refund_address` is `None`, restrict `request_refund` to the account identified by `deposit_msg.recipient_id` (or require a signature from that account), so only the intended recipient can register a refund address.

2. **Persist the caller as the authorized refund initiator**: Store `env::predecessor_account_id()` in `RefundRequest` and enforce that only that account (or DAO/Operator) can call `execute_refund` for that request.

These changes mirror the fix applied in the referenced Strata report: persist the user's chosen parameter at request time and enforce it during permissionless execution.

### Proof of Concept

1. Alice deposits 1 BTC to the bridge address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`.
2. The relayer goes offline; `verify_deposit` is never called.
3. Alice prepares a `request_refund` call with `refund_address = "bc1q_alice..."`.
4. Attacker Eve observes the `LogDepositAddress` event, reconstructs `deposit_msg`, and submits `request_refund(deposit_msg, "bc1q_eve...", tx_bytes, vout, proof)` in the same or earlier block.
5. Eve's call succeeds; `RefundRequest { refund_address: "bc1q_eve..." }` is stored.
6. Alice's call reverts: `"Refund request already exists for this UTXO"`.
7. After `unsafe_refund_timelock_sec` (assuming DAO does not reject), Eve or anyone calls `execute_refund(utxo_storage_key)`.
8. The bridge builds and signs a Bitcoin transaction paying `"bc1q_eve..."` the full deposit minus gas fee.
9. Alice's 1 BTC is permanently transferred to Eve.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-518)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L104-104)
```rust
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
```
