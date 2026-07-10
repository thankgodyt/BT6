The call path is fully confirmed. Let me trace every line precisely.

**Confirmed call chain:**

`execute_refund` (public, no ACL) [1](#0-0) 
→ `internal_execute_refund` (Zcash: async via promise) [2](#0-1) 
→ `execute_refund_callback` (`#[private]`) [3](#0-2) 
→ `finalize_refund_with_psbt` [4](#0-3) 

The critical guard in `finalize_refund_with_psbt`:

```rust
if !self.check_account_exists(&caller) {
    self.internal_set_account(&caller, crate::Account::new(&caller));
}
self.require_pending_sign_capacity(&caller);   // line 342
``` [5](#0-4) 

`require_pending_sign_capacity` uses a strict `<` comparison against a default limit of **1**:

```rust
require!(
    ...pending_sign_count() < self.get_max_pending_sign_txs(account_id),
    "Too many pending sign transactions"
);
``` [6](#0-5) 

Default limit is `unwrap_or(1)`: [7](#0-6) 

`pending_sign_count()` counts **all** entries in `btc_pending_sign_ids` regardless of type (withdrawal, refund, active UTXO management): [8](#0-7) 

A withdrawal adds to `btc_pending_sign_ids` here: [9](#0-8) 

An entry is only removed from `btc_pending_sign_ids` after **all inputs are signed** (moved to `btc_pending_verify_list`): [10](#0-9) 

`cancel_withdraw` (the only user-facing escape valve) is **operator-gated**: [11](#0-10) 

---

### Title
Pending withdrawal blocks `execute_refund` for the same account under default `pending_tx_limit = 1` — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
`finalize_refund_with_psbt` calls `require_pending_sign_capacity` without exempting refund-type operations. With the default per-account limit of 1, a user who has one pending withdrawal in the `PendingSign` stage cannot execute a refund for a separate deposit UTXO until the withdrawal is fully signed or an operator cancels it.

### Finding Description
`btc_pending_sign_ids` is a flat `HashSet<String>` that accumulates IDs for all pending-sign operations: withdrawals, refunds, and active UTXO management. `require_pending_sign_capacity` checks `pending_sign_count() < max_pending_sign_txs` with a hard default of 1. There is no type-based exemption for refunds.

A user who:
1. Initiates a withdrawal (burns nBTC → `btc_pending_sign_ids.len()` becomes 1), and
2. Has a separate deposit UTXO with an approved refund request,

will receive a panic `"Too many pending sign transactions"` when calling `execute_refund` for that second UTXO. The withdrawal entry stays in `btc_pending_sign_ids` until all inputs are signed; the user cannot cancel the withdrawal themselves (`cancel_withdraw` requires `Role::DAO` or `Role::Operator`).

### Impact Explanation
The user's deposit UTXO is stuck in a non-executable refund state for the duration of the withdrawal's signing phase. The user has no self-service path to unblock it: they cannot cancel the withdrawal, and `execute_refund` will keep panicking. Operator intervention is required. This violates the invariant that a user must always be able to execute a refund for their own deposit regardless of pending withdrawal state.

Impact: **Medium** — attacker-triggered (self-triggered) temporary locking of bridged funds; no permanent loss, but requires operator action to resolve.

### Likelihood Explanation
Reachable by any user who holds nBTC (enabling a withdrawal) and simultaneously has a deposit UTXO awaiting refund. The default limit of 1 makes this trivially triggerable. No privileged role is needed.

### Recommendation
Exempt refund-type operations from `require_pending_sign_capacity`, or maintain a separate counter for withdrawal-type pending sign IDs vs. refund-type ones. Concretely, `finalize_refund_with_psbt` should skip the capacity check (or use a separate, higher limit) since a refund is a recovery operation that must always be available to the user.

### Proof of Concept
State setup (Bitcoin or Zcash):
1. User deposits UTXO A → gets nBTC.
2. User deposits UTXO B (relayer never calls `verify_deposit`).
3. User calls `request_refund` for UTXO B → `RefundRequest` stored.
4. User initiates withdrawal (burns nBTC from UTXO A) → `btc_pending_sign_ids = {withdraw_tx_id}`, `len() == 1`.
5. Timelock passes for UTXO B refund.
6. User calls `execute_refund(utxo_storage_key_B)`.
7. `finalize_refund_with_psbt` → `require_pending_sign_capacity` → `1 < 1` is false → **panic "Too many pending sign transactions"**.
8. User cannot sign the withdrawal themselves to clear the slot (they can, but only if MPC cooperates); cannot cancel the withdrawal (operator-only).
9. UTXO B refund is stuck until operator acts.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L283-298)
```rust
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-342)
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
```

**File:** contracts/satoshi-bridge/src/account.rs (L99-101)
```rust
    pub fn pending_sign_count(&self) -> u32 {
        u32::try_from(self.btc_pending_sign_ids.len()).unwrap_or(u32::MAX)
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L105-111)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
```rust
    pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
        require!(
            self.get_account(account_id)
                .unwrap_or_else(|| {
                    env::panic_str(&format!("ERR_ACCOUNT_NOT_REGISTERED: {}", account_id))
                })
                .pending_sign_count()
                < self.get_max_pending_sign_txs(account_id),
            "Too many pending sign transactions"
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L131-133)
```rust
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L198-207)
```rust
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
                if is_original_tx {
                    account
                        .btc_pending_verify_list
                        .insert(btc_pending_sign_id.clone());
                }
```
