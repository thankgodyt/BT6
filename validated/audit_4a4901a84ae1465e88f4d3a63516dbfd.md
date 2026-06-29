### Title
`#[private]` Guard on `resume_promise` Breaks `storage_deposit`, Permanently Locking Bridged Tokens - (File: `near/omni-bridge/src/storage.rs`)

### Summary

`storage_deposit` calls `self.resume_promise(...)` as a direct Rust method call. Because `resume_promise` is annotated `#[private]`, the NEAR SDK inserts a runtime check that panics whenever `predecessor_account_id != current_account_id`. When any external user calls `storage_deposit`, `predecessor_account_id` is that user — not the contract — so the check always fails, `storage_deposit` always panics, and the yield/resume mechanism for `init_transfer` is permanently broken.

### Finding Description

The `storage_deposit` function is the public entry point for users to register storage so that a pending `init_transfer` (which was suspended via `env::promise_yield_create`) can be resumed. [1](#0-0) 

At the end of `storage_deposit`, the contract calls:

```rust
self.resume_promise(&account_id).detach();
``` [2](#0-1) 

`resume_promise` is declared as:

```rust
#[private]
pub fn resume_promise(&self, account_id: &AccountId) -> PromiseOrValue<()> { ... }
``` [3](#0-2) 

The NEAR SDK `#[private]` macro expands to a guard at the top of the function body:

```rust
if near_sdk::env::current_account_id() != near_sdk::env::predecessor_account_id() {
    near_sdk::env::panic_str("Method is private");
}
```

Because `self.resume_promise(...)` is a direct Rust method call — not a cross-contract call — `predecessor_account_id` inside `resume_promise` is still the original external caller of `storage_deposit`, never the contract itself. The guard therefore always fires, panicking the entire transaction.

This is structurally identical to the reported bug: a retry/resume path makes a direct internal call to a function that enforces a caller-identity check, so the check always fails.

### Impact Explanation

The `init_transfer` yield/resume flow works as follows:

1. A user sends tokens via `ft_on_transfer` → `init_transfer`.
2. If the user lacks sufficient storage balance, execution is suspended with `env::promise_yield_create("init_transfer_resume", ...)` and a pending entry is recorded in `init_transfer_promises`.
3. The user is expected to call `storage_deposit` to fund storage, which should trigger `resume_promise` → `env::promise_yield_resume(...)` to unblock the suspended transfer. [4](#0-3) 

Because `storage_deposit` always panics (step 3 above), no suspended `init_transfer` can ever be resumed. The tokens the user already sent to the bridge in step 1 are permanently locked inside the contract with no recovery path.

### Likelihood Explanation

This is triggered by any user who initiates an `init_transfer` without sufficient pre-deposited storage balance — a normal, documented usage path. The `storage_deposit` function is the only mechanism to unblock such transfers. Every such user is affected unconditionally; no special conditions or attacker knowledge are required.

### Recommendation

Replace the direct internal call with a self-directed cross-contract call so that `predecessor_account_id` inside `resume_promise` becomes `current_account_id`:

```rust
// Instead of:
self.resume_promise(&account_id).detach();

// Use:
Self::ext(env::current_account_id())
    .resume_promise(&account_id)
    .detach();
```

This mirrors the remediation described in the referenced report: use an external call to properly set the caller identity before invoking the access-controlled function.

Alternatively, extract the internal logic of `resume_promise` into a private helper without the `#[private]` guard, and call that helper directly from `storage_deposit`.

### Proof of Concept

1. User calls `token.ft_transfer_call(bridge, amount, msg)` with an `InitTransfer` message targeting a foreign chain.
2. `ft_on_transfer` → `init_transfer` finds the user has no storage balance; it suspends execution via `env::promise_yield_create("init_transfer_resume", ...)` and records the yield ID in `init_transfer_promises`.
3. User calls `bridge.storage_deposit(None)` with sufficient NEAR attached.
4. Inside `storage_deposit`, `self.resume_promise(&account_id)` is called directly.
5. The `#[private]` guard fires: `predecessor_account_id` (the user) ≠ `current_account_id` (the bridge) → panic "Method is private".
6. The entire `storage_deposit` transaction reverts. The user's NEAR is refunded, but the suspended `init_transfer` remains blocked forever.
7. The tokens from step 1 are permanently locked in the bridge with no admin or user recovery path. [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/storage.rs (L140-184)
```rust
    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) -> StorageBalance {
        let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
        let amount = env::attached_deposit();
        let storage = self.accounts_balances.get(&account_id).map_or_else(
            || {
                let min_required_storage_balance = self.required_balance_for_account();
                let available = amount
                    .checked_sub(min_required_storage_balance)
                    .near_expect(StorageError::NotEnoughStorageBalanceAttached {
                        required: min_required_storage_balance,
                        attached: amount,
                    });
                StorageBalance {
                    total: amount,
                    available,
                }
            },
            |mut storage| {
                storage.total = storage.total.saturating_add(amount);
                storage.available = storage.available.saturating_add(amount);
                storage
            },
        );
        self.accounts_balances.insert(&account_id, &storage);

        self.resume_promise(&account_id).detach();

        storage
    }

    #[private]
    pub fn resume_promise(&self, account_id: &AccountId) -> PromiseOrValue<()> {
        if let Some(promise_id) = &self.init_transfer_promises.get(account_id) {
            let result = env::promise_yield_resume(promise_id, []);
            env::log_str(&format!("Resume promise. Result: {result}"));

            if !result {
                return Self::ext(env::current_account_id())
                    .resume_promise(account_id)
                    .into();
            }
        }
        PromiseOrValue::Value(())
    }
```

**File:** near/omni-bridge/src/lib.rs (L586-617)
```rust
            let promise_index = env::promise_yield_create(
                "init_transfer_resume",
                json!({
                    "transfer_message": transfer_message,
                    "message_storage_account_id": message_storage_account_id,
                    "storage_owner": signer_id,
                })
                .to_string()
                .as_bytes(),
                INIT_TRANSFER_RESUME_GAS,
                GasWeight(0),
                PROMISE_REGISTER_ID,
            );

            let yield_id: CryptoHash = env::read_register(PROMISE_REGISTER_ID)
                .near_expect(BridgeError::ReadPromiseRegister)
                .try_into()
                .near_expect(BridgeError::ReadPromiseYieldId);

            let required_storage_balance = self.add_promise(&message_storage_account_id, &yield_id);

            self.update_storage_balance(
                env::current_account_id(),
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            env::log_str(&format!(
                "Yield init transfer until storage is available at {message_storage_account_id}"
            ));

            PromiseOrPromiseIndexOrValue::PromiseIndex(promise_index)
```

**File:** near/omni-bridge/src/lib.rs (L621-646)
```rust
    #[private]
    #[allow(clippy::needless_pass_by_value)]
    pub fn init_transfer_resume(
        &mut self,
        transfer_message: TransferMessage,
        message_storage_account_id: AccountId,
        storage_owner: AccountId,
        #[callback_result] response: Result<(), PromiseError>,
    ) -> U128 {
        self.remove_promise(&message_storage_account_id);
        if response.is_err() {
            env::log_str("Init transfer resume timeout");
        }

        if let Err(err) = self.try_to_transfer_balance_from_message_account(
            &message_storage_account_id,
            NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
            &storage_owner,
            self.required_balance_for_init_transfer_message(transfer_message.clone()),
        ) {
            env::log_str(&format!("Error paying native fee and storage: {err}"));
            return transfer_message.amount;
        }

        self.init_transfer_internal(transfer_message, storage_owner)
    }
```
