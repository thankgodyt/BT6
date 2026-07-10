### Title
Attacker Can Hijack Victim's BTC Refund Address via Unauthenticated `request_refund` Race - (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `request_refund` flow contains no caller-authentication check and a hard uniqueness guard in `request_refund_callback`. Because the `deposit_msg` is publicly emitted on-chain via `LogDepositAddress` events, any NEAR account can race to submit a `request_refund` for a victim's unfinalized deposit using an attacker-controlled `refund_address`. Once the attacker's request is stored, the victim's own `request_refund` call is permanently blocked by the hard `require` at `refund.rs:544-547`, and the victim has no self-rescue path — only DAO/Operator intervention can prevent the BTC from being sent to the attacker.

---

### Finding Description

**Public disclosure of `deposit_msg`**

`get_user_deposit_address` emits the full `deposit_msg` as a NEAR event:

```rust
Event::LogDepositAddress {
    deposit_msg,
    path,
    deposit_address: deposit_address.clone(),
}
.emit();
``` [1](#0-0) 

This makes every field of `deposit_msg` — including `recipient_id` — permanently public on-chain.

**No caller authentication in `request_refund`**

The public entry point imposes no check that the caller is the `recipient_id` embedded in `deposit_msg`. The only conditional check is for the optional `gas_fee` parameter:

```rust
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
    gas_fee: Option<U128>,
) -> Promise {
    if gas_fee.is_some() {
        // only DAO/Operator check here
    }
    self.internal_request_refund(deposit_msg, refund_address, ...)
}
``` [2](#0-1) 

When `gas_fee` is `None` (the normal user path), any NEAR account can call `request_refund` with any `deposit_msg` and any `refund_address`.

**`internal_request_refund` only validates `refund_address` when `deposit_msg.refund_address` is pre-set**

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [3](#0-2) 

When `deposit_msg.refund_address` is `None` — the common case for standard deposits — the `refund_address` parameter is accepted verbatim from the caller with no ownership check.

**Hard uniqueness guard blocks the victim permanently**

In `request_refund_callback`, after the light-client proof resolves:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

Once the attacker's request is stored, this hard `require` permanently prevents the victim from submitting their own request with the correct `refund_address`. There is no override or replacement mechanism.

**Victim has no self-rescue path**

`reject_refund` only allows rejection by DAO/Operator, or when the UTXO has already been verified via `verify_deposit`:

```rust
require!(
    is_privileged || is_already_deposited,
    "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
);
``` [5](#0-4) 

The victim (who is neither DAO/Operator nor able to trigger `verify_deposit` for an unfinalized deposit) cannot reject the fraudulent request themselves.

**`execute_refund` is permissionless and pays the stored `refund_address`**

```rust
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
}
``` [6](#0-5) 

No role restriction. After the `unsafe_refund_timelock_sec` (default 14 days) elapses, anyone — including the attacker — can call `execute_refund`, and the BTC is sent to the attacker's stored `refund_address`.

---

### Impact Explanation

An attacker who races to submit `request_refund` before the victim, using an attacker-controlled Bitcoin address, causes:

1. The victim's own `request_refund` to permanently revert ("Refund request already exists for this UTXO").
2. The victim's deposited BTC to be locked for up to 14 days (`unsafe_refund_timelock_sec`).
3. If the DAO/Operator does not reject the fraudulent request within the timelock window, the BTC is irreversibly sent to the attacker's Bitcoin address — a complete theft of user funds.

This matches **Critical** (significant loss/theft of user funds) if the DAO fails to intervene, and **Medium** (attacker-triggered temporary locking requiring operator intervention) otherwise.

---

### Likelihood Explanation

- The `deposit_msg` is publicly emitted on-chain by `get_user_deposit_address` and is trivially observable by any NEAR indexer.
- Unfinalized deposits (where `verify_deposit` was never called) are observable on the Bitcoin blockchain.
- The attacker only needs to pay the anti-spam storage deposit (`required_balance_for_request_refund`) — a small NEAR amount — to execute the attack.
- No special privileges, leaked keys, or majority attacks are required.
- Relayer outages, which leave deposits unfinalized, are a realistic operational scenario.
- The 14-day window means the DAO must actively monitor all refund requests; a single missed fraudulent request results in permanent fund loss.

---

### Recommendation

1. **Authenticate the caller**: In `request_refund` (or `request_refund_callback`), require that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`. This ensures only the intended recipient can initiate a refund for their deposit.

2. **Alternatively, require a pre-authorized `refund_address`**: Reject `request_refund` calls where `deposit_msg.refund_address` is `None` from unprivileged callers, forcing users to embed their refund address in the `deposit_msg` at deposit time (where it is cryptographically bound to the deposit address derivation).

3. **Allow the victim to override**: If a refund request already exists for a UTXO, allow the `recipient_id` to replace it with a new `refund_address`, rather than hard-reverting.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The full `deposit_msg` is emitted as a `LogDepositAddress` event on NEAR.
2. Alice sends 1 BTC to the generated deposit address on Bitcoin.
3. The relayer fails to call `verify_deposit`; Alice's deposit is unfinalized.
4. Bob (attacker) observes the `LogDepositAddress` event and the Bitcoin deposit on-chain.
5. Bob calls `request_refund(deposit_msg=Alice's, refund_address="bob_btc_address", tx_bytes=..., vout=0, proof=...)` with the required storage deposit attached.
6. The light-client proof resolves successfully. `request_refund_callback` stores a `RefundRequest` with `refund_address = "bob_btc_address"`.
7. Alice calls `request_refund` with her own `refund_address`. The callback hits:
   ```
   require!(!self.data().refund_requests.contains_key(&utxo_storage_key), "Refund request already exists for this UTXO");
   ```
   Alice's call reverts. She has no further recourse.
8. After 14 days (`unsafe_refund_timelock_sec`), Bob calls `execute_refund`. The bridge constructs a Bitcoin transaction paying 1 BTC (minus gas fee) to `"bob_btc_address"`.
9. Alice's 1 BTC is permanently transferred to Bob.

### Citations

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L510-535)
```rust
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L564-567)
```rust
        require!(
            is_privileged || is_already_deposited,
            "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L582-589)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```
