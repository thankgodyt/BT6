### Title
Unbound `refund_address` in `request_refund` Allows Attacker to Redirect BTC Refunds - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

When a user deposits BTC using a `DepositMsg` with `refund_address: None`, any unprivileged NEAR account can call `request_refund` with the correct (public) `deposit_msg` and an attacker-controlled `refund_address`. The BTC transaction proof only validates transaction inclusion and that the output script matches the `deposit_msg`-derived address — it does not bind to the `refund_address` parameter. An attacker can frontrun the legitimate user's refund request, locking the user out and redirecting the BTC refund to the attacker's address.

### Finding Description

The deposit address is derived as `sha256(json(deposit_msg))`, which cryptographically binds the BTC output to the full `deposit_msg`. However, when `deposit_msg.refund_address` is `None`, the `refund_address` argument passed to `request_refund` is a free parameter — it is stored verbatim in the `RefundRequest` and later used as the BTC destination in `execute_refund`, but it is never committed to by the BTC transaction or the `deposit_msg` hash.

In `internal_request_refund`, the only check on `refund_address` when `deposit_msg.refund_address` is `None` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
// If deposit_msg.refund_address is None → no check at all
``` [1](#0-0) 

The `request_refund_callback` then verifies only that the BTC output script matches the `deposit_msg`-derived address — it does not validate `refund_address` at all:

```rust
require!(
    deposit_script_pubkey == output.script_pubkey,
    "Output script_pubkey does not match deposit address"
);
``` [2](#0-1) 

The stored `refund_address` is then used directly when building the refund transaction in `execute_refund` → `build_refund_output`. [3](#0-2) 

The `deposit_msg` is fully public: it is emitted as a `LogDepositAddress` event when `get_user_deposit_address` is called, and the BTC transaction is visible on-chain. [4](#0-3) 

`request_refund` is callable by any NEAR account (confirmed by tests where `"alice"` and `"bob"` — regular users — call it directly, and failures are business-logic errors, not access-control errors). [5](#0-4) 

Once a refund request exists for a UTXO, a second `request_refund` for the same UTXO is rejected:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [6](#0-5) 

This means the attacker's frontrun permanently blocks the legitimate user from registering their own refund request until the DAO/Operator manually rejects the malicious one.

### Impact Explanation

**Stuck bridge state requiring operator intervention (Medium) / theft of user BTC (Critical if operator is unavailable).**

The attacker frontruns the legitimate user's `request_refund` call, storing their own BTC address as the refund destination. The legitimate user is blocked from creating a competing refund request. After `unsafe_refund_timelock_sec` elapses without DAO/Operator rejection, anyone can call `execute_refund`, causing the bridge's MPC-signed transaction to send the user's BTC to the attacker's address. The user's BTC is permanently lost.

Even if the DAO rejects the malicious request, the user's BTC is temporarily locked and the user must re-submit — requiring active operator monitoring and intervention for every deposit with `refund_address: None`. [7](#0-6) 

### Likelihood Explanation

- `deposit_msg` is emitted publicly as a `LogDepositAddress` event; the BTC transaction is visible on-chain.
- `request_refund` is open to any NEAR account with a small attached deposit.
- The attacker only needs to observe the BTC mempool or confirmed transactions and submit a NEAR transaction before the legitimate user.
- The attack is cheap, requires no privileged access, and is repeatable against any deposit where `deposit_msg.refund_address` is `None`.

### Recommendation

Bind the `refund_address` to the `deposit_msg` at deposit time. Specifically:

1. **Require `deposit_msg.refund_address` to always be set** when a user wants refund eligibility, so the refund destination is committed to in the BTC deposit address derivation (and thus in the on-chain BTC output). Any `request_refund` call with a mismatched address would then fail the `deposit_script_pubkey == output.script_pubkey` check.

2. **Alternatively**, if `refund_address: None` must remain supported, restrict `request_refund` to the `recipient_id` named in `deposit_msg`, or require the caller to prove ownership of the `recipient_id` account. This prevents a third party from registering a refund on behalf of another user with an attacker-controlled destination.

3. **At minimum**, add a check in `request_refund_callback` that the caller (`env::predecessor_account_id()` of the outer call, passed through) matches `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`.

### Proof of Concept

```
1. Alice calls get_user_deposit_address({recipient_id: "alice", refund_address: None})
   → Bridge emits LogDepositAddress event with full deposit_msg
   → Alice receives deposit_address_A

2. Alice sends 1 BTC to deposit_address_A (confirmed on-chain)

3. Relayer is slow / down; verify_deposit not yet called.

4. Attacker observes LogDepositAddress event and the BTC transaction.

5. Attacker calls:
   request_refund(
     deposit_msg = {recipient_id: "alice", refund_address: None},
     refund_address = "attacker_btc_address",
     tx_bytes = <Alice's BTC tx>,
     vout = 0,
     proof = <valid Merkle proof>
   )
   → request_refund_callback: script_pubkey matches (deposit_msg is correct) ✓
   → RefundRequest stored with refund_address = "attacker_btc_address"

6. Alice calls request_refund → PANIC: "Refund request already exists for this UTXO"

7. DAO/Operator does not notice or is unavailable.

8. After unsafe_refund_timelock_sec, attacker calls execute_refund(utxo_storage_key).
   → Bridge builds BTC tx paying 1 BTC to "attacker_btc_address"
   → MPC signs and broadcasts
   → Alice's 1 BTC is stolen.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L198-228)
```rust
    /// Validate the attached storage deposit and resolve the timelock that must
    /// elapse before this refund can be executed. Shared by the Bitcoin and
    /// Zcash `execute_refund` entrypoints.
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-535)
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
