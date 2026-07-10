### Title
Permissionless `request_refund` Allows Attacker to Redirect User BTC Refunds to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

`request_refund` is a permissionless public function. When a user's `DepositMsg` has `refund_address: None`, any NEAR account can call `request_refund` for that UTXO and supply an arbitrary attacker-controlled BTC address. The stored `RefundRequest.refund_address` is then used verbatim when `execute_refund` builds the MPC-signed PSBT, redirecting the user's BTC to the attacker.

### Finding Description

The `request_refund` function in `contracts/satoshi-bridge/src/api/bridge.rs` is placed in a `#[trusted_relayer] #[near] impl Contract` block but carries **no** function-level `#[trusted_relayer]` attribute of its own, making it callable by any NEAR account. [1](#0-0) 

Inside `internal_request_refund`, the only guard on `refund_address` is: [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the user did not pre-authorize a BTC return address), the check is skipped entirely and the caller-supplied `refund_address` is accepted without restriction.

After the Light Client verifies the transaction, `request_refund_callback` stores the attacker-supplied address verbatim: [3](#0-2) 

A duplicate-request guard then blocks the legitimate user from submitting their own `request_refund` for the same UTXO: [4](#0-3) 

When `execute_refund` is later called (also permissionless after the timelock), `finalize_refund_with_psbt` uses the stored `refund_address` to build the PSBT output: [5](#0-4) 

The MPC then signs a transaction paying the attacker's BTC address.

The system acknowledges this risk by applying a longer `unsafe_refund_timelock_sec` for requests where `deposit_msg.refund_address` is `None`: [6](#0-5) 

However, this mitigation is purely operational — it relies on the DAO/Operator actively monitoring and rejecting malicious requests within the timelock window. If the DAO is offline, slow, or overwhelmed, the attacker's request proceeds to execution.

### Impact Explanation

An attacker who observes an unfinalized deposit (via on-chain `LogDepositAddress` events and Bitcoin mempool monitoring) where `deposit_msg.refund_address = None` can redirect the entire deposit amount (minus gas fee) to their own BTC address. This constitutes direct theft of user funds. The `verified_deposit_utxo` set is also marked after `execute_refund`, permanently blocking the legitimate user from ever claiming via `verify_deposit`.

**Impact: Critical** — Significant theft of user BTC funds.

### Likelihood Explanation

The attacker must:
1. Monitor NEAR events for `LogDepositAddress` to learn `deposit_msg` values (public, on-chain)
2. Monitor Bitcoin for deposits to those addresses (public)
3. Detect that `verify_deposit` was never called (observable on-chain)
4. Pay 2 NEAR as anti-spam fee
5. Wait for `unsafe_refund_timelock_sec` without DAO intervention

Relayer downtime is a realistic scenario (the refund system exists precisely for this case). The 2 NEAR cost is low relative to any meaningful BTC deposit. The DAO rejection window is the only barrier, and it is not guaranteed.

**Likelihood: Medium**

### Recommendation

Restrict `request_refund` so that when `deposit_msg.refund_address` is `None`, only the `deposit_msg.recipient_id` (the intended nBTC recipient) can supply a `refund_address`. Add a check in `internal_request_refund`:

```rust
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.recipient_id,
        "Only the deposit recipient can set refund_address when not pre-authorized"
    );
}
```

Alternatively, require `deposit_msg.refund_address` to always be set at deposit time (enforced in `get_user_deposit_address`) so the permissionless path is never reachable with an uncontrolled address.

### Proof of Concept

1. Alice generates a deposit address with `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`. The `LogDepositAddress` event is emitted publicly.
2. Alice sends 0.01 BTC to the deposit address. The relayer goes offline; `verify_deposit` is never called.
3. Attacker Eve observes the event and the Bitcoin transaction. Eve calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
     refund_address = "bc1q<eve_address>",
     tx_bytes = <alice_deposit_tx>,
     vout = 0,
     proof = <valid_merkle_proof>,
     gas_fee = None
   )
   ```
   attaching 2 NEAR. The Light Client validates the proof; `request_refund_callback` stores `refund_address = "bc1q<eve_address>"`.
4. Alice tries to call `request_refund` with her own BTC address — it panics: `"Refund request already exists for this UTXO"`.
5. After `unsafe_refund_timelock_sec` elapses (DAO does not reject), Eve calls `execute_refund(utxo_storage_key)`. The bridge builds a PSBT paying `bc1q<eve_address>`.
6. Eve calls `sign_btc_transaction` to obtain the MPC signature, broadcasts the transaction, and receives Alice's BTC.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
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

**File:** contracts/satoshi-bridge/src/refund.rs (L323-325)
```rust
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
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
