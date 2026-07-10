### Title
Front-Running `request_refund` Redirects User BTC Refund to Attacker Address — (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is publicly callable by any NEAR account and accepts an arbitrary `refund_address` parameter when `deposit_msg.refund_address` is `None`. An attacker who observes a pending `request_refund` transaction can front-run it with the same proof but a different `refund_address` pointing to their own BTC wallet. Because the contract enforces uniqueness per UTXO, the victim's subsequent call is rejected, and after the timelock the attacker executes the refund and receives the victim's BTC.

---

### Finding Description

`request_refund` in `bridge.rs` (lines 508–535) is in a `#[trusted_relayer] #[near] impl Contract` block but carries **no individual `#[trusted_relayer]` attribute** on the function itself. Comparing with functions in the same block that are relayer-restricted (`verify_refund_finalize` at line 604, `remove_refund_pending_tx_id` at line 624), those carry the individual attribute; `request_refund`, `reject_refund`, and `execute_refund` do not. The block-level attribute adds management helpers, not per-method enforcement. Therefore `request_refund` is callable by any NEAR account. [1](#0-0) 

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case — it is an optional field), **any caller may supply any BTC address**. The `deposit_msg` itself is public information derivable from the BTC transaction and the NEAR call arguments.

In `request_refund_callback`, the duplicate-request guard rejects the second submission for the same UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

So whichever call lands first wins. The attacker's request is stored with their BTC address; the victim's call panics.

`execute_refund` is also unrestricted (no individual `#[trusted_relayer]`, no role check): [4](#0-3) 

After `unsafe_refund_timelock_sec` (default 14 days per `config.rs` line 9), the attacker calls `execute_refund` and the MPC pipeline sends the BTC to their address. [5](#0-4) 

---

### Impact Explanation

The attacker receives the victim's BTC deposit (minus the gas fee). The victim's `request_refund` call fails permanently for that UTXO (the duplicate guard blocks re-submission while the attacker's request exists). This constitutes direct theft of user funds — a Critical impact under "Significant loss, theft, destruction, or permanent locking of user or protocol funds."

The DAO/Operator can reject the attacker's request within the 14-day window, but this is a manual, reactive defense that is not guaranteed. If the DAO is slow, offline, or the attacker times the submission during an operational gap, the attack succeeds. Even if rejected, the victim must re-submit and faces the same race again.

---

### Likelihood Explanation

- NEAR transactions are publicly observable before finalization (mempool monitoring is straightforward).
- The attacker needs only to copy `deposit_msg`, `tx_bytes`, `vout`, and `proof` from the victim's pending call and substitute their own `refund_address`.
- The non-refundable storage deposit required by `request_refund` is a minor cost relative to any meaningful BTC deposit.
- Users who did not set `deposit_msg.refund_address` at deposit time (the optional field defaults to `None`) are fully exposed.
- The 14-day `unsafe_refund_timelock_sec` gives the attacker ample time to wait; it does not prevent the attack, only delays execution.

---

### Recommendation

Bind the `refund_address` to the caller's identity at request time, or require that `deposit_msg.refund_address` always be set (non-optional) so the destination is committed at deposit time and cannot be overridden by a third party. A minimal fix is to store `env::predecessor_account_id()` alongside the request and require that only the original requester (or DAO/Operator) can execute the refund for requests where `deposit_msg.refund_address` was `None`.

---

### Proof of Concept

1. **Victim** sends BTC to the bridge deposit address derived from `deposit_msg = { recipient_id: "victim.near", refund_address: None, ... }`. The deposit is never finalized.
2. **Victim** submits `request_refund(deposit_msg, "victim_btc_addr", tx_bytes, vout, proof, None)` to the NEAR bridge contract.
3. **Attacker** observes the pending NEAR transaction, extracts `deposit_msg`, `tx_bytes`, `vout`, and `proof`.
4. **Attacker** submits `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)` with higher gas, ensuring it is processed first.
5. `request_refund_callback` stores `RefundRequest { refund_address: "attacker_btc_addr", ... }` keyed by `{txid}@{vout}`.
6. Victim's callback panics: `"Refund request already exists for this UTXO"`. Victim's attached storage deposit is lost.
7. After 14 days, **attacker** calls `execute_refund("{txid}@{vout}", None)`. The MPC pipeline constructs and signs a BTC transaction paying `"attacker_btc_addr"`.
8. Attacker calls `verify_refund_finalize` once the BTC transaction confirms. Victim's BTC is permanently redirected. [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L496-581)
```rust
    #[private]
    pub fn request_refund_callback(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        gas_fee: Option<u128>,
    ) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

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

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

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

        true
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
