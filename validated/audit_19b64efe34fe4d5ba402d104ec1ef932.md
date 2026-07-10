### Title
Attacker Can Front-Run `request_refund` to Redirect Refunded BTC to Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

When a user calls `request_refund` with a `DepositMsg` whose `refund_address` field is `None`, an attacker can observe the call in the NEAR mempool and front-run it with identical parameters but a substituted `refund_address` pointing to the attacker's own Bitcoin address. Because the contract enforces a strict one-request-per-UTXO rule, the attacker's request lands first, the victim's is rejected, and after the timelock the attacker calls `execute_refund` to receive the victim's BTC.

---

### Finding Description

The `request_refund` public entry point accepts a caller-supplied `refund_address` parameter. The only guard against address substitution is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

This check is only enforced when `deposit_msg.refund_address` is `Some`. When it is `None` — the common case for users who did not pre-commit a refund address — any caller may supply any `refund_address` and the contract accepts it without verifying the caller is the intended beneficiary.

The contract then enforces a first-come-first-served rule in the callback:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [2](#0-1) 

Because all parameters needed to construct a valid `request_refund` call (`deposit_msg`, `tx_bytes`, `vout`, `proof`) are visible in the victim's pending NEAR transaction, an attacker copies them verbatim, substitutes their own Bitcoin address for `refund_address`, and submits with sufficient priority to land first. The victim's subsequent call fails with "Refund request already exists for this UTXO".

The `request_refund` function is publicly callable. The `#[trusted_relayer]` attribute appears only at the `impl`-block level; individual functions that are actually gated carry a redundant function-level `#[trusted_relayer]` (e.g. `verify_deposit`). Functions in the same block that are clearly public — `reject_refund`, `execute_refund` — carry no function-level `#[trusted_relayer]`, confirming the impl-level attribute does not restrict individual methods. `request_refund` has only `#[payable]` and `#[pause]` at the function level. [3](#0-2) 

After the attacker's request is stored, `execute_refund` is also publicly callable: [4](#0-3) 

The refund PSBT is built using `refund_request.refund_address` — the attacker's address — and the MPC network signs and broadcasts it, sending the victim's BTC to the attacker. [5](#0-4) 

---

### Impact Explanation

The victim's BTC (deposit amount minus gas fee) is permanently transferred to the attacker's Bitcoin address. The victim loses their entire refund. This constitutes direct theft of user funds via an unauthorized redirection of bridge-controlled BTC — matching the **Critical** impact class: *significant loss or theft of user funds*.

---

### Likelihood Explanation

- NEAR transactions are observable in the mempool before finalization.
- All parameters required to construct the attack (`deposit_msg`, `tx_bytes`, `vout`, `proof`) are present in the victim's pending call.
- The attacker only needs to change `refund_address` and attach the required NEAR storage deposit (`required_balance_for_request_refund()`).
- The only operational mitigation is DAO/Operator rejection during `unsafe_refund_timelock_sec`, which requires active monitoring and is not a protocol-level guarantee.
- No special privileges, leaked keys, or majority attacks are required.

Likelihood: **Medium** (requires mempool observation and timely front-run, but is mechanically straightforward for any motivated attacker).

---

### Recommendation

1. **Bind `refund_address` to the caller**: Require that the caller's NEAR account ID is recorded alongside the refund request, and that only the original requester (or DAO/Operator) can execute the refund.
2. **Require pre-committed refund address**: Enforce that `deposit_msg.refund_address` is always `Some`, making the refund address part of the deposit commitment and immune to substitution.
3. **Analog to the ETH2.0 fix**: Just as the recommended fix checks the deposit root before submission to ensure no front-run occurred, this bridge should verify that the `refund_address` is cryptographically bound to the deposit (e.g., via `deposit_msg.refund_address`) before accepting a caller-supplied value.

---

### Proof of Concept

1. Alice sends BTC to her deposit address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`.
2. The deposit is never finalized (e.g., relayer failure).
3. Alice constructs and submits `request_refund(deposit_msg, "alice_btc_addr", tx_bytes, vout, proof, None)` to the NEAR network.
4. Attacker Eve observes Alice's pending transaction in the NEAR mempool.
5. Eve copies all parameters and submits `request_refund(deposit_msg, "eve_btc_addr", tx_bytes, vout, proof, None)` with higher priority.
6. Eve's call lands first; `request_refund_callback` stores `RefundRequest { refund_address: "eve_btc_addr", ... }`. [6](#0-5) 

7. Alice's call fails: "Refund request already exists for this UTXO".
8. After `unsafe_refund_timelock_sec` elapses (assuming DAO does not intervene), Eve calls `execute_refund(utxo_storage_key, None)`.
9. The bridge builds a refund PSBT paying `"eve_btc_addr"`, the MPC network signs it, and Alice's BTC is sent to Eve. [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-401)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

        let deposit_msg = refund_request.deposit_msg();
        let path = get_deposit_path(&deposit_msg);
        let vutxo = VUTXO::Current(UTXO {
            path,
            tx_bytes: refund_request.tx_bytes.0.clone(),
            vout: refund_request.vout,
            balance: u64::try_from(refund_request.amount)
                .unwrap_or_else(|_| env::panic_str("Amount overflow")),
        });

        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };

        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());

        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
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
