### Title
Unauthenticated `request_refund` Allows Any Caller to Redirect BTC Refunds to an Arbitrary Address When `deposit_msg.refund_address` Is Unset - (File: contracts/satoshi-bridge/src/api/bridge.rs)

---

### Summary

The `request_refund` function is publicly callable with no caller-identity check. When a deposit was made with `deposit_msg.refund_address = None`, any party who knows the `deposit_msg` can submit a refund request naming an arbitrary BTC address as the destination. Because only one request per UTXO is accepted, a front-running attacker can permanently block the legitimate depositor's refund and, if the DAO/Operator fails to reject within the timelock, redirect the deposited BTC to an attacker-controlled address.

---

### Finding Description

`request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` carries only a `#[pause]` guard; there is no check that the caller is the original depositor or a trusted relayer. [1](#0-0) 

Inside `internal_request_refund`, the only validation of `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` the branch is skipped entirely, so the caller-supplied `refund_address` is accepted without restriction.

In `request_refund_callback` the contract verifies that the transaction output matches the deposit address derived from `deposit_msg` via `get_deposit_path`: [3](#0-2) 

This proves the UTXO is real, but it says nothing about who is entitled to the refund. The `refund_address` is stored verbatim and later used to build the Bitcoin output in `build_refund_output`: [4](#0-3) 

A duplicate-request guard prevents a second request for the same UTXO: [5](#0-4) 

So whichever caller wins the race owns the refund destination.

The only protocol-level mitigation is `unsafe_refund_timelock_sec`, a longer timelock applied when `deposit_msg.refund_address` is `None`, intended to give the DAO/Operator time to call `reject_refund`: [6](#0-5) 

This is a trust assumption, not a cryptographic guarantee. If the DAO/Operator is unavailable, slow, or compromised, the attacker's request executes and the BTC is irreversibly sent to the attacker's address.

---

### Impact Explanation

If the DAO/Operator does not reject in time, the depositor's BTC is permanently redirected to an attacker-controlled Bitcoin address. This constitutes a significant, permanent loss of user funds — matching the **Critical** impact tier (theft/permanent loss of bridged funds). Even in the best case where the DAO/Operator does reject, the legitimate depositor's funds are temporarily locked and the depositor must pay a second storage deposit to re-submit.

---

### Likelihood Explanation

The `deposit_msg` is not a secret. It is passed in plaintext to `verify_deposit` / `verify_deposit_v2` by relayers; any failed or pending relayer call is visible in NEAR transaction history. An attacker monitoring NEAR for bridge activity can extract the `deposit_msg` for any unfinalized deposit and race to call `request_refund` before the depositor does. The attack requires no special privilege, no leaked key, and no majority hash-power — only knowledge of a public NEAR transaction and the ability to submit a transaction.

---

### Recommendation

1. **Require `deposit_msg.refund_address` to be pre-committed.** Reject `request_refund` calls where `deposit_msg.refund_address` is `None`, forcing users to embed their BTC refund address in the deposit message before sending BTC. Because `get_deposit_path` hashes the entire `deposit_msg`, a pre-committed address is cryptographically bound to the deposit UTXO.

2. **Or restrict the caller.** Add an access-control check so that only the NEAR account encoded in `deposit_msg.recipient_id` (or a DAO/Operator role) may call `request_refund`, preventing third-party front-running.

3. **Or require a signed attestation** from `deposit_msg.recipient_id` authorising the supplied `refund_address`.

---

### Proof of Concept

1. Alice deposits 1 BTC to the bridge using a `deposit_msg` with `recipient_id = "alice.near"` and `refund_address = None`. The deposit address is derived from `sha256(json(deposit_msg))`.
2. The relayer calls `verify_deposit_v2` but the call fails (e.g., light-client not yet synced). The `deposit_msg` is now visible in NEAR transaction history.
3. Eve, an attacker, reads the `deposit_msg` from the failed relayer transaction.
4. Eve calls `request_refund(deposit_msg, "eve_btc_address", tx_bytes, vout, proof, None)` before Alice does.
5. `request_refund_callback` confirms the UTXO is real and stores the request with `refund_address = "eve_btc_address"`.
6. Alice calls `request_refund` — it panics: `"Refund request already exists for this UTXO"`.
7. The DAO/Operator does not notice within `unsafe_refund_timelock_sec`.
8. Eve calls `execute_refund`; the bridge signs and broadcasts a Bitcoin transaction paying 1 BTC (minus gas fee) to `eve_btc_address`.
9. Alice's BTC is permanently lost.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L517-525)
```rust
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
