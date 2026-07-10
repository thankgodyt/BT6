### Title
Unauthenticated `request_refund` Allows Frontrunning to Redirect BTC Refunds to Attacker Address — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is a public, unauthenticated function. Any NEAR account can submit a refund request for any BTC UTXO with an arbitrary `refund_address`. Because the function makes an async cross-contract call to the Light Client before storing the request, an attacker who observes a legitimate user's pending `request_refund` call can race to submit their own call for the same UTXO with an attacker-controlled BTC address. If the attacker's callback lands first, the user's callback panics and the user's non-refundable NEAR storage deposit is lost. After the `unsafe_refund_timelock_sec` elapses, the attacker can call `execute_refund` and redirect the user's BTC to their own address.

---

### Finding Description

`request_refund` carries no caller authentication: [1](#0-0) 

It delegates to `internal_request_refund`, which only validates `refund_address` against `deposit_msg.refund_address` when that optional field is `Some`: [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case for users who did not pre-authorize a BTC return address), the `refund_address` argument is accepted verbatim from whoever calls the function. The function then fires an async Light Client verification promise: [3](#0-2) 

In the callback, the only guard against a duplicate is: [4](#0-3) 

This check is a first-writer-wins race. An attacker who observes the user's pending `request_refund` call (all NEAR transactions are public) can immediately submit an identical call with the same `deposit_msg` and `tx_bytes` but with `refund_address` set to an attacker-controlled BTC address. Whichever callback resolves first wins the slot. The loser's callback panics and the attached NEAR deposit — explicitly described as non-refundable — is burned: [5](#0-4) 

The winning refund request is then stored with the attacker's BTC address. Because `execute_refund` is also public (no role restriction), after `unsafe_refund_timelock_sec` elapses anyone — including the attacker — can call it and the bridge will construct and sign a PSBT paying the attacker's address: [6](#0-5) 

The `unsafe_refund_timelock_sec` path is taken precisely because `deposit_msg.refund_address` is `None`: [7](#0-6) 

The longer timelock is the only mitigation — it gives DAO/Operator a window to call `reject_refund`. If they do not act, the BTC is sent to the attacker.

---

### Impact Explanation

**Guaranteed (griefing / stuck state):** The legitimate user's `request_refund` callback panics, their non-refundable NEAR storage deposit is lost, and their BTC UTXO is locked behind the attacker's refund request. Recovering requires DAO/Operator intervention (`reject_refund`), which is a stuck bridge state requiring operator action.

**Conditional (theft):** If DAO/Operator does not reject the attacker's request before `unsafe_refund_timelock_sec` expires, the attacker calls `execute_refund`, the bridge's MPC network signs a PSBT paying the attacker's BTC address, and the user's BTC is permanently redirected. This constitutes significant loss of user funds.

---

### Likelihood Explanation

The attack requires only a public NEAR account and the ability to observe a pending transaction — both trivially available. The `deposit_msg` and `tx_bytes` are fully visible in the mempool/transaction history. The attacker's cost is a small NEAR storage deposit and gas. The user's cost is their BTC deposit plus the lost NEAR anti-spam fee. The attack is reachable on every `request_refund` call where `deposit_msg.refund_address` is `None`.

---

### Recommendation

Bind the refund request to the caller's NEAR account ID. In `request_refund_callback`, derive the `refund_address` exclusively from `deposit_msg.refund_address` when it is `Some`, and when it is `None`, require that the caller prove ownership (e.g., store `predecessor_account_id()` at request time and only allow that account to later change or confirm the BTC address). Alternatively, require `deposit_msg.refund_address` to always be set before a refund request is accepted, eliminating the free-choice `refund_address` path entirely.

---

### Proof of Concept

1. User calls `request_refund` on the bridge contract with `deposit_msg` (where `refund_address` is `None`), `refund_address = "user_btc_addr"`, and valid `tx_bytes`/`proof`. The call is visible in the NEAR transaction pool.
2. Attacker immediately calls `request_refund` with the identical `deposit_msg` and `tx_bytes` but `refund_address = "attacker_btc_addr"`. Both calls are now racing through the Light Client cross-contract call.
3. Attacker's `request_refund_callback` resolves first. The check at line 544 passes (no existing entry). The refund request is stored keyed by `{tx_id}@{vout}` with `refund_address = "attacker_btc_addr"`.
4. User's `request_refund_callback` resolves. The check at line 544 fails — "Refund request already exists for this UTXO" — the callback panics. The user's attached NEAR deposit is not returned.
5. Attacker waits for `unsafe_refund_timelock_sec` to elapse without DAO/Operator intervention.
6. Attacker calls `execute_refund(utxo_storage_key, None)`. The bridge builds a PSBT spending the user's deposit UTXO, requests an MPC signature, and broadcasts a Bitcoin transaction paying `"attacker_btc_addr"`. The user's BTC is stolen.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L488-492)
```rust
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
    /// # Arguments
```

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L170-183)
```rust
        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```
