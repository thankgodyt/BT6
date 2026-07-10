### Title
Unbound `refund_address` in `request_refund` Allows Any Caller to Redirect Unfinalized Deposits to Attacker-Controlled BTC Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

When a user deposits BTC using a `DepositMsg` with `refund_address: None`, any unprivileged NEAR account can call `request_refund` and supply an arbitrary attacker-controlled BTC address as the `refund_address`. Because the contract never verifies that the caller is the `recipient_id` encoded in the `DepositMsg`, and because the `DepositMsg` is fully public (emitted on-chain via `LogDepositAddress`), an attacker can front-run or race the legitimate depositor's refund request and redirect the BTC to themselves.

---

### Finding Description

The `DepositMsg` struct encodes the intended NEAR recipient: [1](#0-0) 

The deposit address is derived deterministically from the SHA-256 hash of the serialized `DepositMsg`, making the full `DepositMsg` public knowledge once the user calls `get_user_deposit_address` (which emits a `LogDepositAddress` event). [2](#0-1) 

`request_refund` is callable by any NEAR account (the flow diagrams in the project docs show the user calling it directly; it is `#[payable]` with no `#[trusted_relayer]` attribute on the function itself): [3](#0-2) 

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [4](#0-3) 

When `deposit_msg.refund_address` is `None` the branch is skipped entirely. There is **no check** that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. The attacker-supplied `refund_address` is stored verbatim in the `RefundRequest`: [5](#0-4) 

The contract itself acknowledges the risk by applying a longer `unsafe_refund_timelock_sec` for this case, relying on DAO/Operator to reject suspicious requests: [6](#0-5) 

However, this is a governance-dependent mitigation, not a cryptographic one. If the DAO is slow, unavailable, or does not notice the malicious request before the timelock expires, `execute_refund` can be called by anyone and the BTC is sent to the attacker's address via `build_refund_output`: [7](#0-6) 

---

### Impact Explanation

An attacker who observes Alice's `DepositMsg` (with `refund_address: None`) from on-chain events can call `request_refund` with their own BTC address before or concurrently with Alice. After `unsafe_refund_timelock_sec` elapses without DAO rejection, the attacker calls `execute_refund`, and the bridge's MPC-signed transaction sends Alice's BTC to the attacker's address. Alice's deposited BTC is permanently stolen.

**Impact class**: Critical — significant theft of user funds (BTC that was deposited but never finalized as nBTC).

---

### Likelihood Explanation

- The `DepositMsg` is fully public: it is emitted in the `LogDepositAddress` event every time a user queries their deposit address.
- `request_refund` is callable by any NEAR account with a small attached storage deposit.
- The only mitigation is DAO/Operator rejection within `unsafe_refund_timelock_sec`. If the DAO is inattentive, rate-limited by many simultaneous malicious requests, or the timelock is configured short, the attack succeeds.
- No cryptographic proof of ownership over the `recipient_id` is required from the attacker.

**Likelihood**: Medium — the attack is straightforward but depends on DAO inaction during the timelock window.

---

### Recommendation

Bind the `refund_address` to the `recipient_id` encoded in the `DepositMsg`. Specifically:

1. **Require `deposit_msg.refund_address` to be set at deposit time** (i.e., reject `request_refund` when `deposit_msg.refund_address` is `None`), so the refund destination is committed to cryptographically at the time the deposit address is derived.
2. **Or**, require that the caller of `request_refund` is `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`, so only the intended NEAR recipient can specify an arbitrary BTC refund address.

Either approach eliminates the ability for an unprivileged third party to redirect the refund.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: "alice.near", refund_address: None, ... })`. The bridge emits `LogDepositAddress` with the full `DepositMsg`.
2. Alice sends BTC to the returned address. The deposit is never finalized (relayer is down).
3. Bob observes Alice's `DepositMsg` from the `LogDepositAddress` event.
4. Bob calls `request_refund(deposit_msg = Alice's DepositMsg, refund_address = "bc1q_bob_address", tx_bytes = ..., vout = ..., proof = ...)` with the required storage deposit attached.
5. `internal_request_refund` checks `deposit_msg.refund_address` — it is `None`, so the branch is skipped. Bob's address is stored in the `RefundRequest`.
6. The `unsafe_refund_timelock_sec` elapses without DAO rejection.
7. Bob calls `execute_refund(utxo_storage_key)`. The bridge builds a BTC transaction paying `bc1q_bob_address` and requests an MPC signature.
8. Bob broadcasts the signed transaction. Alice's BTC is sent to Bob's address.

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L12-28)
```rust
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
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
