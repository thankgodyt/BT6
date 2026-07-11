### Title
Unprivileged Caller Can Permanently Lock Victim's BTC by Front-Running `execute_refund` — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`execute_refund` carries no caller-identity check. Any NEAR account can execute a refund on behalf of any pending refund request, becoming the owner of the resulting `BTCPendingInfo`. If the attacker then abandons the signing step, and the DAO subsequently rejects the refund request (a normal administrative action), the UTXO is permanently stranded in `verified_deposit_utxo` with no recovery path, locking the victim's BTC forever.

---

### Finding Description

`execute_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` is decorated only with `#[payable]` and `#[pause(except(roles(Role::DAO)))]`. There is no check that the caller is the original refund requester. [1](#0-0) 

Inside `resolve_execute_refund_timelock`, the only caller-related check is whether the caller is a privileged role (for timelock bypass). No ownership check is performed. [2](#0-1) 

In `internal_execute_refund` (Bitcoin path), `env::predecessor_account_id()` — the attacker — is passed directly as the `caller` to `finalize_refund_with_psbt`, making the attacker the `account_id` of the resulting `BTCPendingInfo`. [3](#0-2) 

`finalize_refund_with_psbt` then:
1. Inserts the `BTCPendingInfo` under the attacker's account.
2. Inserts the UTXO key into `verified_deposit_utxo` (blocking any future `verify_deposit`).
3. Sets `refund_request.executed = true`. [4](#0-3) 

`sign_btc_transaction` — the next required step — also has no caller-identity check; it is open to any NEAR account. [5](#0-4) 

**Attack sequence:**

1. Attacker observes a pending `RefundRequest` on-chain (all state is public).
2. Attacker calls `execute_refund(utxo_storage_key, …)` attaching only the small storage deposit (`required_balance_for_execute_refund()`).
3. `BTCPendingInfo` is created under the attacker's account; UTXO is added to `verified_deposit_utxo`; `executed = true`.
4. Attacker never calls `sign_btc_transaction`. The refund is stuck.
5. The victim tries to call `execute_refund` again. `load_refund_request_for_execute` allows re-execution when `executed == true`, but `finalize_refund_with_psbt` panics with `"pending info already exist"` because the same PSBT ID (same inputs/outputs/fee) already exists. [6](#0-5) 

**Why DAO intervention makes it worse:**

The DAO may call `reject_refund` to clean up the stale request. `internal_reject_refund` removes the entry from `refund_requests` but does **not** clear `verified_deposit_utxo`. [7](#0-6) 

After rejection, the relayer calls `remove_refund_pending_tx_id` to remove the stale `BTCPendingInfo`. Now the victim tries to recover:

- Calls `request_refund` again → new `RefundRequest` created with `executed = false`.
- Calls `execute_refund` → `load_refund_request_for_execute` checks: [6](#0-5) 

`verified_deposit_utxo.contains(utxo_key)` is `true` and `refund_request.executed` is `false` → **panics with "UTXO already verified via deposit, cannot refund"**. There is no contract function to remove a key from `verified_deposit_utxo`. The BTC is permanently locked.

---

### Impact Explanation

The victim's BTC deposited to the bridge-derived address is permanently unrecoverable:
- `verify_deposit` is blocked because the UTXO is in `verified_deposit_utxo`.
- `execute_refund` is blocked for the same reason (once the refund request is gone or `executed == false`).
- No administrative function exists to clear `verified_deposit_utxo`.

This constitutes **permanent locking of user funds**, matching the Critical allowed impact: *"Significant loss, theft, destruction, or permanent locking of user or protocol funds."*

---

### Likelihood Explanation

- All `RefundRequest` state is public on-chain; an attacker can monitor for new requests.
- The only cost is the `required_balance_for_execute_refund()` storage deposit (a small NEAR amount, far less than any non-trivial BTC deposit).
- The attacker needs no special role, no leaked key, and no privileged access.
- The permanent-lock outcome requires the DAO to subsequently reject the refund request, which is a normal administrative action (e.g., if the DAO believes the refund is stale or the deposit was processed).

Likelihood: **Medium** (requires on-chain monitoring and a small deposit; permanent outcome depends on DAO action, but temporary DoS is unconditional).

---

### Recommendation

1. **Restrict `execute_refund` to the original requester or privileged roles.** Store the requester's `AccountId` in `RefundRequest` at `request_refund_callback` time, and assert `env::predecessor_account_id() == refund_request.requester || is_privileged` inside `execute_refund`.
2. **Add a privileged function to remove a UTXO from `verified_deposit_utxo`** (DAO-only) to allow recovery from stuck states.
3. **Restrict `sign_btc_transaction`** to the `account_id` stored in the `BTCPendingInfo`, or to privileged roles, to prevent third-party interference with in-flight operations.

---

### Proof of Concept

```
# Setup: victim has a pending RefundRequest for utxo_key = "abc123@0"
# refund_request.executed = false, verified_deposit_utxo does NOT contain "abc123@0"

# Step 1: Attacker front-runs execute_refund
attacker.call("execute_refund", {
    utxo_storage_key: "abc123@0",
    chain_specific_data: null
}, deposit = required_balance_for_execute_refund())
# → BTCPendingInfo created under attacker.account_id
# → verified_deposit_utxo.insert("abc123@0")
# → refund_request.executed = true

# Step 2: Attacker does nothing (never calls sign_btc_transaction)

# Step 3: DAO rejects the stale refund request
dao.call("reject_refund", { utxo_storage_key: "abc123@0" })
# → refund_requests.remove("abc123@0")
# → verified_deposit_utxo still contains "abc123@0"

# Step 4: Relayer removes stale BTCPendingInfo
relayer.call("remove_refund_pending_tx_id", { tx_id: "<psbt_id>" })
# → btc_pending_infos.remove("<psbt_id>")

# Step 5: Victim tries to recover
victim.call("request_refund", { ... })  # succeeds, new request with executed=false
victim.call("execute_refund", { utxo_storage_key: "abc123@0", ... })
# → load_refund_request_for_execute:
#   verified_deposit_utxo.contains("abc123@0") = true
#   refund_request.executed = false
#   → PANIC: "UTXO already verified via deposit, cannot refund"

# Victim's BTC is permanently locked. No recovery path exists.
```

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-401)
```rust
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L35-43)
```rust
        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
```

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-43)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```
