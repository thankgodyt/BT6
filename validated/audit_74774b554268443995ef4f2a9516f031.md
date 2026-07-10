### Title
Permissionless `request_refund` Allows Any Caller to Redirect a Victim's BTC Refund to an Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is a public, unpermissioned function. It accepts a caller-supplied `refund_address` and stores it verbatim in the `RefundRequest`. There is no check that the caller is the `deposit_msg.recipient_id`. When a deposit was made without a pre-committed `refund_address` in the `deposit_msg`, any third party can submit a refund request for that UTXO and supply their own BTC address, causing the bridge to eventually send the victim's BTC to the attacker.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` (lines 508–535) is callable by any NEAR account:

```rust
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
``` [1](#0-0) 

The only guard on `refund_address` is inside `internal_request_refund` in `contracts/satoshi-bridge/src/refund.rs` (lines 154–159):

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

This guard is only active when the original `deposit_msg` already contains a `refund_address`. The `DepositMsg` struct shows this field is optional and defaults to `None` for most users:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub refund_address: Option<String>,
``` [3](#0-2) 

When `deposit_msg.refund_address` is `None`, the caller's `refund_address` argument is accepted unconditionally and stored in the `RefundRequest`:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // attacker-controlled
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [4](#0-3) 

Later, `finalize_refund_with_psbt` builds the Bitcoin output directly from `refund_request.refund_address`:

```rust
let refund_address = refund_request.refund_address.clone();
``` [5](#0-4) 

```rust
pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
    let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
        .expect("Invalid refund address");
    let refund_script_pubkey = refund_addr.script_pubkey().expect("Invalid refund script_pubkey");
    TxOut { value: ..., script_pubkey: refund_script_pubkey }
}
``` [6](#0-5) 

There is no check anywhere in this path that `env::predecessor_account_id() == deposit_msg.recipient_id`.

The protocol applies a longer `unsafe_refund_timelock_sec` when `deposit_msg.refund_address` is `None`, giving the DAO a window to reject:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [7](#0-6) 

However, this is a reactive mitigation that depends on continuous DAO monitoring. If the DAO misses or is slow to reject the request, `execute_refund` becomes callable by anyone and the BTC is irrevocably sent to the attacker's address.

---

### Impact Explanation

If the DAO fails to reject the malicious `RefundRequest` within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund`, the bridge's MPC pipeline signs a Bitcoin transaction paying the attacker's BTC address, and the victim's deposited BTC is permanently lost. This is a direct theft of user funds from the bridge.

**Impact: Critical** — Significant loss/theft of user funds (BTC) via attacker-controlled redirection of the refund output.

---

### Likelihood Explanation

The attack requires:
1. A deposit UTXO that has not yet been finalized via `verify_deposit` (e.g., a failed or delayed deposit).
2. The original `deposit_msg.refund_address` to be `None` (the common case for standard deposits).
3. The DAO to miss or be unable to reject the malicious `RefundRequest` within `unsafe_refund_timelock_sec`.

Conditions 1 and 2 are routine. Condition 3 is the only barrier, and it is not a cryptographic or protocol-level guarantee — it is an operational assumption. An attacker can time the attack during periods of low DAO activity, submit many requests to overwhelm monitoring, or simply wait out a long timelock.

**Likelihood: Medium** — Operationally gated but not cryptographically prevented; realistic for a motivated attacker.

---

### Recommendation

Add a caller-identity check in `internal_request_refund` (or `request_refund`) requiring that `env::predecessor_account_id() == deposit_msg.recipient_id`, unless the caller holds a privileged role (DAO/Operator/RefundOperator). This mirrors the fix recommended in the Opus report: restrict the permissionless action to the rightful owner.

Alternatively, require that `deposit_msg.refund_address` is always set (non-`None`) before a refund request can be submitted by a non-privileged caller, so the destination is always committed to at deposit time and cannot be overridden by a third party.

---

### Proof of Concept

1. Alice sends BTC to the bridge deposit address derived from her `deposit_msg` (with `refund_address: None`). The deposit is not yet finalized (relayer is delayed).
2. Bob (attacker) observes Alice's BTC transaction on-chain. He calls `request_refund` with Alice's `deposit_msg`, Alice's `tx_bytes`/`vout`/`proof`, and **Bob's own BTC address** as `refund_address`. He attaches the required NEAR storage deposit.
3. `internal_request_refund` verifies the BTC transaction via the light client. Since `deposit_msg.refund_address` is `None`, Bob's address passes unchecked. A `RefundRequest` is stored with `refund_address = Bob's BTC address`.
4. The `unsafe_refund_timelock_sec` elapses. The DAO does not reject the request.
5. Bob (or anyone) calls `execute_refund`. The bridge builds a Bitcoin transaction paying Bob's address and submits it to MPC for signing.
6. The signed transaction is broadcast. Alice's BTC is sent to Bob. Alice receives nothing.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L324-324)
```rust
        let refund_address = refund_request.refund_address.clone();
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
