### Title
Attacker Can Lock Refund Address for Another User's Deposit UTXO, Redirecting BTC Refunds — (`contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` does not verify that the caller is the intended recipient of the deposit (`deposit_msg.recipient_id`). Any NEAR account can submit a refund request for any deposit UTXO and supply an arbitrary attacker-controlled BTC address as `refund_address`. Once stored, the refund request is immutable and a duplicate-check guard prevents the legitimate depositor from submitting their own request, locking the refund destination to the attacker's address.

---

### Finding Description

`request_refund` in `api/bridge.rs` is callable by any account (the test suite confirms regular user "alice" calls it directly). It accepts a `deposit_msg` and a caller-supplied `refund_address`. The only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None` (the common case — it is an optional field), this guard is skipped entirely and the caller's arbitrary `refund_address` is accepted without restriction. [2](#0-1) 

The callback then stores the attacker-supplied address permanently:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-controlled
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [3](#0-2) 

A subsequent call by the legitimate depositor is blocked by the duplicate guard:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

The `deposit_msg` needed to reconstruct the deposit path is publicly emitted in `LogDepositAddress` events when `get_user_deposit_address` is called, so an attacker can trivially obtain it for any deposit. [5](#0-4) 

When `execute_refund` is later called (by a relayer or DAO), the BTC is sent to the attacker's address stored in `refund_request.refund_address`. [6](#0-5) 

---

### Impact Explanation

A depositor who did not embed a `refund_address` in their `deposit_msg` (the optional field is `None`) can have their refund permanently redirected to an attacker-controlled BTC address. The legitimate user is simultaneously blocked from filing their own refund request. If the DAO/Operator does not reject the malicious request within `unsafe_refund_timelock_sec`, the depositor's BTC is irrecoverably sent to the attacker. This constitutes a significant loss of user funds.

The `unsafe_refund_timelock_sec` path is applied precisely because the refund address was not pre-authorized in the `deposit_msg`:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [7](#0-6) 

This mitigation is operational, not cryptographic — it relies on the DAO/Operator noticing and acting in time.

---

### Likelihood Explanation

- `deposit_msg` is publicly available from on-chain events.
- The attacker only needs to pay the storage deposit (`required_balance_for_request_refund`) and submit a valid BTC inclusion proof (the same proof the legitimate user would submit — it is public BTC blockchain data).
- Deposits with `deposit_msg.refund_address = None` are the common case (the field is optional and many users will omit it).
- The attack can be executed by any NEAR account with no special privileges.

---

### Recommendation

Add a caller-identity check inside `internal_request_refund` (or its callback) to ensure only the `deposit_msg.recipient_id` can submit a refund request for that deposit:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id
        || self.acl_has_any_role(vec![Role::DAO.into(), Role::Operator.into()],
                                  env::predecessor_account_id()),
    "Only the deposit recipient or a privileged role may request a refund"
);
```

Alternatively, require that `deposit_msg.refund_address` is always set (non-optional) so the refund destination is committed at deposit time and cannot be overridden by a third party.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `deposit_msg = { recipient_id: "alice", refund_address: None, ... }`. The event log reveals the full `deposit_msg`.
2. Alice sends BTC to the derived deposit address. The relayer does not finalize the deposit (e.g., light client lag).
3. Bob (attacker) reads Alice's `deposit_msg` from the event log and calls:
   ```
   request_refund(
       deposit_msg = Alice's deposit_msg,
       refund_address = "bob_btc_address",
       tx_bytes = <Alice's BTC tx>,
       vout = 0,
       proof = <valid inclusion proof>,
       gas_fee = None
   )
   ```
4. `request_refund_callback` stores `RefundRequest { refund_address: "bob_btc_address", ... }` for Alice's UTXO.
5. Alice attempts `request_refund` with her own address → panics: `"Refund request already exists for this UTXO"`.
6. After `unsafe_refund_timelock_sec` elapses (and if DAO/Operator does not call `reject_refund`), anyone calls `execute_refund` → Alice's BTC is sent to Bob's address.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L323-325)
```rust
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

```

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
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
