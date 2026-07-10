### Title
Zcash `execute_refund` Makes Async Cross-Contract Call Before State Update, Enabling Duplicate Pending Refund Transactions - (File: `contracts/satoshi-bridge/src/zcash_utils/refund.rs`)

---

### Summary

The Zcash path of `execute_refund` issues an async cross-contract call to fetch the current block height before any state is mutated. Because NEAR cross-contract calls are not atomic, a second `execute_refund` call for the same UTXO can be submitted and processed before the first callback fires. If the two callbacks resolve at different block heights they produce distinct PSBT IDs, so both `finalize_refund_with_psbt` invocations succeed, inserting two separate `BTCPendingInfo` entries for the same deposit UTXO. `execute_refund` carries no caller-identity restriction, so any unprivileged NEAR account can trigger this.

---

### Finding Description

`execute_refund` (Bitcoin path) builds its PSBT synchronously and updates state in one atomic step. The Zcash path cannot do this because Zcash transaction construction requires the current consensus branch ID, which is derived from the live block height. The bridge therefore issues an async call to the light client first: [1](#0-0) 

```rust
pub(crate) fn internal_execute_refund(
    &mut self,
    utxo_storage_key: String,
    timelock_sec: u64,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let caller = env::predecessor_account_id();
    PromiseOrValue::Promise(
        self.get_last_block_height_promise().then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_EXECUTE_REFUND_CALLBACK)
                .execute_refund_callback(
                    utxo_storage_key,
                    caller,
                    timelock_sec,
                    chain_specific_data,
                ),
        ),
    )
}
```

No state is mutated before this promise is dispatched. The `refund_request.executed` flag and `verified_deposit_utxo` membership are only written inside `finalize_refund_with_psbt`, which runs in the callback: [2](#0-1) 

The pre-execution guard in `load_refund_request_for_execute` explicitly permits re-entry when `executed == true`: [3](#0-2) 

```rust
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)
        || refund_request.executed,
    "UTXO already verified via deposit, cannot refund"
);
```

This means that once the first callback fires (setting `executed = true`), every subsequent `execute_refund` call also passes the guard. Because `execute_refund` has no caller-identity restriction: [4](#0-3) 

any account can call it. Each call that resolves at a distinct block height produces a unique `btc_pending_id` (the PSBT ID is derived from transaction content, which includes `last_block_height`). The uniqueness check in `finalize_refund_with_psbt`: [5](#0-4) 

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
```

only blocks collisions on the same PSBT ID. Different block heights → different IDs → both insertions succeed.

---

### Impact Explanation

Multiple `BTCPendingInfo` entries are created for the same deposit UTXO. All are eligible for MPC signing via `sign_btc_transaction`. All can be broadcast to the Zcash network. Only one can confirm on-chain (the UTXO is spent once). The remaining entries are permanently stuck until `verify_refund_finalize` removes the refund request and `remove_refund_pending_tx_id` is called for each stale entry. During this window the bridge holds stale signed-but-unconfirmable Zcash transactions, MPC signing slots are consumed, and the attacker's account accumulates pending-sign entries that count against `require_pending_sign_capacity`. No nBTC is minted or unlocked without a corresponding on-chain deposit, so there is no direct fund theft.

**Severity: Low** — publicly reachable stuck-state in a production bridge path without direct theft.

---

### Likelihood Explanation

`execute_refund` is a public, payable function with no role restriction. Any NEAR account that attaches the required storage deposit can call it. The only cost to the attacker is the NEAR storage deposit per call. The Zcash path's async block-height fetch creates a one-block window for a race condition, and the intentional re-execution design (`executed == true` bypasses the guard) means the window is open indefinitely after the first execution. Exploitation requires no special knowledge beyond the `utxo_storage_key`, which is a public on-chain value (`{tx_id}@{vout}`).

---

### Recommendation

1. **Restrict re-execution to privileged callers.** The re-execution path (consensus branch change) should require `Role::DAO` or `Role::Operator`. Add an access-control check in `resolve_execute_refund_timelock` or `load_refund_request_for_execute` when `executed == true`.

2. **Set a "pending execution" flag before the async XCC.** Introduce a boolean field (e.g., `pending_execution: bool`) in `RefundRequest`. Set it to `true` before dispatching `get_last_block_height_promise` and clear it in the callback. Reject concurrent `execute_refund` calls while the flag is set.

3. **Follow the stated security invariant.** `CLAUDE.md` line 73 states: *"Mutate state (mark UTXO used, update balances) BEFORE cross-contract calls."* The Zcash `execute_refund` path violates this invariant. [6](#0-5) 

---

### Proof of Concept

1. A deposit UTXO `abc@0` exists with a valid refund request. The timelock has passed.
2. **Block N:** Attacker A calls `execute_refund("abc@0")`. The bridge dispatches `get_last_block_height_promise` (height H1). No state is updated.
3. **Block N+1:** Attacker A's callback fires with `last_block_height = H1`. `finalize_refund_with_psbt` inserts `BTCPendingInfo` with `pending_id_1` (derived from PSBT at H1). Sets `executed = true`.
4. **Block N+1:** Attacker B calls `execute_refund("abc@0")`. `load_refund_request_for_execute` passes because `executed == true`. The bridge dispatches `get_last_block_height_promise` (height H2 = H1+1).
5. **Block N+2:** Attacker B's callback fires with `last_block_height = H2`. `finalize_refund_with_psbt` inserts `BTCPendingInfo` with `pending_id_2` (different from `pending_id_1`). Both entries now exist.
6. Both `pending_id_1` and `pending_id_2` can be signed via `sign_btc_transaction` and broadcast. Only one confirms. The other is permanently stuck until manual cleanup via `remove_refund_pending_tx_id`. [7](#0-6) [8](#0-7) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L28-47)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let caller = env::predecessor_account_id();
        PromiseOrValue::Promise(
            self.get_last_block_height_promise().then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_EXECUTE_REFUND_CALLBACK)
                    .execute_refund_callback(
                        utxo_storage_key,
                        caller,
                        timelock_sec,
                        chain_specific_data,
                    ),
            ),
        )
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L79-148)
```rust
    #[private]
    pub fn execute_refund_callback(
        &mut self,
        utxo_storage_key: String,
        caller: AccountId,
        timelock_sec: u64,
        chain_specific_data: Option<ChainSpecificData>,
        #[callback_unwrap] last_block_height: u32,
    ) {
        // Enforce the timelock and that the UTXO has not been finalized via deposit.
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);

        let expiry_height = REFUND_EXPIRY_HEIGHT;
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        // Shielded refund routes funds through the Orchard bundle (no transparent
        // output); transparent refund pays a single t-address output.
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };

        let mut psbt = PsbtWrapper::new(
            vec![outpoint],
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(refund_request.refund_address.clone()),
            self.internal_config(),
        );
        psbt.set_input_utxo(vec![deposit_output]);

        // Validate the gas fee covers the Zcash minimum and, for shielded refunds,
        // that the Orchard bundle pays out to `refund_address`.
        self.check_psbt_chain_specific(
            &psbt,
            refund_request.gas_fee,
            refund_request.refund_address.clone(),
        );

        // `validate_orchard_bundle` only checks the recipient and the bundle's
        // internal value balance, not that it matches the deposit economics.
        // Enforce that the shielded output equals deposit - gas, otherwise the
        // resulting transaction would not balance against the chosen gas fee.
        if psbt.has_orchard_bundle() {
            require!(
                psbt.get_orchard_output_amount() == refund_amount,
                format!(
                    "Orchard output amount ({}) does not match refund amount ({})",
                    psbt.get_orchard_output_amount(),
                    refund_amount
                )
            );
        }

        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L230-261)
```rust
    /// Load a refund request and run the common pre-execution checks
    /// (timelock elapsed, not already finalized via deposit).
    pub(crate) fn load_refund_request_for_execute(
        &self,
        utxo_storage_key: &str,
        timelock_sec: u64,
    ) -> RefundRequest {
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();

        let now = nano_to_sec(env::block_timestamp());
        require!(
            u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
            "Refund timelock has not passed yet"
        );

        // Block only if the UTXO was claimed by a deposit. If it was claimed by
        // our own refund (executed == true, which also set verified_deposit_utxo),
        // re-running execute_refund is allowed — re-creating the refund tx, e.g.
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );

        refund_request
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-372)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-401)
```rust
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

**File:** CLAUDE.md (L72-75)
```markdown
### State Management
- Mutate state (mark UTXO used, update balances) BEFORE cross-contract calls
- Create and emit events AFTER all state mutations complete
- **Cross-contract calls are NOT atomic:** Each callback is a separate transaction - must manually rollback state in callback if external call fails
```
