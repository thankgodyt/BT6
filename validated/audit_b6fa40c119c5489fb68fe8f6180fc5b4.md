### Title
Permissionless `request_refund` Allows Attacker to Redirect Victim's BTC Refund to Arbitrary Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`request_refund` is a permissionless function that accepts a caller-supplied `refund_address`. When the original `deposit_msg.refund_address` is `None`, there is no validation that the caller is the original depositor. Any unprivileged NEAR account can submit a refund request for any unfinalized deposit UTXO and set `refund_address` to an attacker-controlled BTC address, front-running the legitimate user and locking them out of their own refund.

### Finding Description

`request_refund` in `bridge.rs` has no access control and no check that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`:

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

The only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case — the field is optional and skipped in serialization), this guard is entirely bypassed and any caller-supplied `refund_address` is accepted verbatim. [3](#0-2) 

Once a refund request is stored, a duplicate-prevention check blocks any subsequent request for the same UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

This means an attacker who front-runs the legitimate user's `request_refund` call permanently locks the victim out of submitting their own refund request for that UTXO.

The `unsafe_refund_timelock_sec` (default 14 days) applies when `deposit_msg.refund_address` is `None`, giving DAO/Operator a window to reject: [5](#0-4) 

However, if the DAO/Operator fails to monitor and reject within 14 days, `execute_refund` becomes callable by anyone and the BTC is sent to the attacker's address. [6](#0-5) 

### Impact Explanation

**Impact: Medium** (with potential escalation to Critical if DAO/Operator is inactive).

An attacker can front-run any unfinalized deposit's refund request and set `refund_address` to their own BTC address. The victim is immediately locked out of submitting their own refund request for that UTXO. If the DAO/Operator fails to reject within 14 days, the attacker executes the refund and steals the victim's BTC. Even if the DAO/Operator rejects, the victim's funds are temporarily locked and they must re-submit, incurring additional storage deposits and delays.

### Likelihood Explanation

**Likelihood: Medium.**

All inputs needed to mount the attack are publicly observable on-chain: the `deposit_msg` is emitted via `LogDepositAddress` events, and the BTC `tx_bytes` and inclusion proof are available from the Bitcoin blockchain. Unfinalized deposits occur whenever a relayer fails to call `verify_deposit` (e.g., due to downtime or congestion). The attacker only needs to monitor for such deposits and submit a refund request before the legitimate user does.

### Recommendation

1. Require that the caller of `request_refund` is the `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`, or restrict `request_refund` to the depositor and privileged roles.
2. Alternatively, when `deposit_msg.refund_address` is `None`, only allow the `deposit_msg.recipient_id` to supply the `refund_address`, and reject calls from any other account.
3. As a defense-in-depth measure, allow the legitimate depositor to override a pending refund request submitted by a third party.

### Proof of Concept

1. Alice deposits BTC to the bridge address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The deposit is never finalized (relayer is down).
2. The `LogDepositAddress` event reveals Alice's `deposit_msg`. The BTC transaction is visible on-chain.
3. Attacker calls `request_refund(deposit_msg=Alice's, refund_address="attacker_btc_addr", tx_bytes=..., vout=0, proof=...)`.
4. The contract stores the refund request with `refund_address = "attacker_btc_addr"`. Alice's subsequent `request_refund` call reverts with `"Refund request already exists for this UTXO"`.
5. After 14 days, if DAO/Operator has not called `reject_refund`, the attacker calls `execute_refund(utxo_storage_key)`.
6. The bridge constructs a BTC transaction paying Alice's deposit amount (minus gas fee) to `"attacker_btc_addr"` and submits it for MPC signing. [7](#0-6)

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L216-228)
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
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-291)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");

        RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        }
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
