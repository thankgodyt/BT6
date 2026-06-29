The code confirms both bypass paths. Let me verify the `TransferMessageStorageAccount::id()` derivation to confirm the deterministic pre-computation claim.

The `TransferMessageStorageAccount` struct used for the hash includes `token`, `amount`, `recipient`, `fee` (including `native_fee`), `sender`, and `msg` — but **not** `origin_nonce` or `destination_nonce`.

Audit Report

## Title
`NativeFeeRestricted` Role Bypass via Message Account Pre-funding and `init_transfer_resume` — (`near/omni-bridge/src/lib.rs`)

## Summary
The `NativeFeeRestricted` role check in `init_transfer` is placed only in the right-hand side of a short-circuit `||` expression. A restricted account can pre-fund the deterministically-derivable message storage account, causing the left branch to succeed and the role check to be silently skipped. A second, independent bypass exists in `init_transfer_resume`, which contains no `NativeFeeRestricted` check at all, allowing a restricted account to trigger the yield path and then fund the message account to resume with `native_fee > 0`.

## Finding Description
In `near/omni-bridge/src/lib.rs`, `init_transfer` evaluates the following condition to decide whether to proceed immediately or yield:

```rust
if self
    .try_to_transfer_balance_from_message_account(
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()                                          // Branch A
    || (self.has_storage_balance(...)
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
                                                      // Branch B — only place the check exists
``` [1](#0-0) 

Due to Rust's short-circuit `||`, if Branch A returns `Ok`, Branch B — which contains the sole `acl_has_role(NativeFeeRestricted)` check — is never evaluated.

The message account ID is computed as a SHA256 hash of `{token, amount, recipient, fee, sender, msg}` plus an optional `external_id`. [2](#0-1) 

Critically, `origin_nonce` and `destination_nonce` are **not** part of the hash. [3](#0-2) 

All inputs to the hash are known to the attacker before submitting the transfer, so the account ID is fully pre-computable off-chain.

`try_to_transfer_balance_from_message_account` returns `Ok` when: the message account exists, its `total >= native_fee`, the signer is registered, and `signer.available + message_account.total >= required_storage + native_fee`. [4](#0-3) 

A `NativeFeeRestricted` attacker can deposit `required_storage + native_fee` into the pre-computed message account via `storage_deposit`, satisfying all conditions for Branch A to return `Ok`, bypassing the role check entirely.

The second bypass path is `init_transfer_resume`, which is invoked when the transfer yields. It contains no `NativeFeeRestricted` check:

```rust
pub fn init_transfer_resume(...) -> U128 {
    self.remove_promise(&message_storage_account_id);
    // ...
    if let Err(err) = self.try_to_transfer_balance_from_message_account(...) {
        return transfer_message.amount;
    }
    self.init_transfer_internal(transfer_message, storage_owner)  // no role check
}
``` [5](#0-4) 

A restricted account can trigger the yield path (by not pre-funding initially, causing both Branch A and Branch B to fail), then call `storage_deposit` for the message account. `storage_deposit` calls `resume_promise`, which resumes the yield and fires `init_transfer_resume` — which proceeds to `init_transfer_internal` with `native_fee > 0` and no role check. [6](#0-5) 

## Impact Explanation
This is a concrete role bypass. The `NativeFeeRestricted` role is an explicit bridge-level access control mechanism defined alongside other protocol roles. [7](#0-6) 

Its bypass allows a restricted account to set arbitrary `native_token_fee` values in outbound bridge transfers, directly executing bridge actions that the protocol explicitly prohibits for that account class. This matches the allowed critical impact: **"Unauthorized transaction, authorization bypass, role bypass... that lets an attacker execute bridge... actions."**

## Likelihood Explanation
The bypass requires no privileged access and no victim interaction. The message account address is fully deterministic and computable off-chain from public transfer parameters. Any `NativeFeeRestricted` account aware of the code path can execute either bypass in two transactions: one `storage_deposit` and one `ft_transfer_call`. The restriction is completely ineffective against any account that inspects the contract logic.

## Recommendation
1. Move the `NativeFeeRestricted` check to the top of `init_transfer`, before the Branch A / Branch B split, so it gates the entire function unconditionally regardless of how storage is paid.
2. Add the same check at the start of `init_transfer_resume`, using `storage_owner` as the signer identity and `transfer_message.fee.native_fee` as the fee value to check.

## Proof of Concept
**Path 1 (pre-fund bypass):**
1. Admin grants `NativeFeeRestricted` to `alice.near`.
2. `alice.near` constructs the `TransferMessageStorageAccount` struct for a transfer with `native_token_fee = 1 NEAR` and computes its `id()` off-chain (SHA256 of borsh-serialized fields, no nonces involved).
3. `alice.near` calls `storage_deposit` on the bridge for that computed account ID, depositing `required_storage_balance + 1 NEAR`.
4. `alice.near` calls `ft_transfer_call` on the token contract targeting the bridge, with `msg` containing `native_token_fee = 1 NEAR`.
5. Inside `init_transfer`, `try_to_transfer_balance_from_message_account` finds the pre-funded account, passes all balance checks, and returns `Ok`.
6. The `||` short-circuits; `acl_has_role(NativeFeeRestricted)` at line 580 is never reached.
7. `init_transfer_internal` is called and the transfer is registered with `native_fee = 1 NEAR`.

**Path 2 (yield/resume bypass):**
1. Same setup. `alice.near` calls `ft_transfer_call` with `native_token_fee = 1 NEAR` without pre-funding the message account.
2. Branch A fails (`MessageAccountNotRegistered`). Branch B fails (`NativeFeeRestricted` check). Transfer yields.
3. `alice.near` calls `storage_deposit` for the message account with sufficient balance.
4. `storage_deposit` triggers `resume_promise`, which resumes the yield and invokes `init_transfer_resume`.
5. `init_transfer_resume` calls `try_to_transfer_balance_from_message_account` — it succeeds — and calls `init_transfer_internal` with `native_fee = 1 NEAR` with no role check performed.

### Citations

**File:** near/omni-bridge/src/lib.rs (L113-129)
```rust
#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    DAO,
    PauseManager,
    UnrestrictedDeposit,
    UpgradableCodeStager,
    UpgradableCodeDeployer,
    MetadataManager,
    UnrestrictedRelayer,
    TokenControllerUpdater,
    NativeFeeRestricted,
    RbfOperator,
    TokenUpgrader,
    TokenLockController,
    RelayerManager,
}
```

**File:** near/omni-bridge/src/lib.rs (L566-584)
```rust
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
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

**File:** near/omni-types/src/lib.rs (L601-608)
```rust
pub struct TransferMessageStorageAccount {
    pub token: OmniAddress,
    pub amount: U128,
    pub recipient: OmniAddress,
    pub fee: Fee,
    pub sender: OmniAddress,
    pub msg: String,
}
```

**File:** near/omni-types/src/lib.rs (L612-620)
```rust
    pub fn id(&self, external_id: Option<String>) -> AccountId {
        let mut bytes = borsh::to_vec(self).unwrap();
        if let Some(external_id) = external_id {
            bytes.extend_from_slice(external_id.as_bytes());
        }
        let hash = utils::sha256(&bytes);
        let implicit_account_id = hex::encode(hash);
        AccountId::try_from(implicit_account_id).unwrap()
    }
```

**File:** near/omni-bridge/src/storage.rs (L141-168)
```rust
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
```

**File:** near/omni-bridge/src/storage.rs (L260-290)
```rust
    pub(crate) fn try_to_transfer_balance_from_message_account(
        &mut self,
        account_id: &AccountId,
        native_fee: NearToken,
        storage_payer: &AccountId,
        required_storage_payer_balance: NearToken,
    ) -> Result<(), StorageError> {
        let balance = self
            .accounts_balances
            .get(account_id)
            .ok_or(StorageError::MessageAccountNotRegistered)?;

        if balance.total < native_fee {
            return Err(StorageError::NotEnoughBalanceForFee);
        }

        let mut storage = self
            .accounts_balances
            .get(storage_payer)
            .ok_or(StorageError::SignerNotRegistered)?;

        storage.available = storage.available.saturating_add(balance.total);

        if storage.available < required_storage_payer_balance.saturating_add(native_fee) {
            return Err(StorageError::SignerNotEnoughBalance);
        }

        self.accounts_balances.insert(storage_payer, &storage);
        self.accounts_balances.remove(account_id);
        Ok(())
    }
```
