Audit Report

## Title
NativeFeeRestricted Role Bypass via Pre-Funded Message Storage Account - (File: near/omni-bridge/src/lib.rs)

## Summary
The `NativeFeeRestricted` role check in `init_transfer` is placed exclusively inside the second branch of a short-circuit `||` condition. An attacker holding the `NativeFeeRestricted` role can pre-fund the deterministically computable message storage account via the permissionless `storage_deposit` function, causing the first branch to return `Ok` and short-circuit the entire condition, bypassing the role check entirely and initiating a bridge transfer with a non-zero `native_token_fee`.

## Finding Description
In `near/omni-bridge/src/lib.rs` at lines 566–581, `init_transfer` selects a storage payer via:

```rust
if self
    .try_to_transfer_balance_from_message_account(...)
    .is_ok()                          // branch 1: NO role check
|| (self.has_storage_balance(...)
    && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
                                      // branch 2: role check only here
``` [1](#0-0) 

When branch 1 succeeds, Rust's `||` short-circuits and branch 2 — including the `NativeFeeRestricted` check — is never evaluated.

`try_to_transfer_balance_from_message_account` succeeds when the virtual message account exists with `total >= native_fee` and the signer's augmented available balance covers `required_storage_payer_balance + native_fee`. [2](#0-1) 

The virtual message account ID is the SHA-256 of a borsh-serialized `TransferMessageStorageAccount`, which contains only `token`, `amount`, `recipient`, `fee`, `sender`, and `msg` — **no nonces** — making it fully computable off-chain before the transfer is submitted. [3](#0-2) 

`storage_deposit` is a permissionless public function that accepts any `account_id` with no restrictions on who may deposit for which account. [4](#0-3) 

The same bypass applies to `init_transfer_resume` (lines 635–645), which calls `try_to_transfer_balance_from_message_account` with no role check before calling `init_transfer_internal`. [5](#0-4) 

## Impact Explanation
This is a confirmed role bypass. The `NativeFeeRestricted` role is an explicit access-control mechanism designed to prevent designated accounts from initiating bridge transfers with a non-zero `native_token_fee`. Bypassing it allows a restricted account to execute an unauthorized bridge action — initiating a cross-chain transfer with a non-zero native fee — which directly matches the allowed critical impact: "Unauthorized transaction, authorization bypass, role bypass... that lets an attacker execute bridge... actions."

## Likelihood Explanation
The attack requires only two on-chain calls (`storage_deposit` then `ft_transfer_call`) and no privileged access beyond holding the `NativeFeeRestricted` role itself. The message account ID is deterministically computable off-chain with no brute force. The attack is fully self-contained, requires no victim interaction, and is repeatable for every transfer the attacker wishes to submit.

## Recommendation
Add an unconditional guard immediately after `TransferMessage` is constructed, before any storage-payment branch is evaluated:

```rust
require!(
    init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
    BridgeError::NativeFeeRestricted.as_ref()
);
```

This ensures the role check cannot be bypassed by any storage-payment path, including the message-account path and the `init_transfer_resume` callback.

## Proof of Concept
1. Grant `NativeFeeRestricted` to `attacker.testnet`. Register `attacker.testnet` in bridge storage (minimum balance only).
2. Off-chain, compute `message_account_id` by borsh-serializing `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }` and SHA-256 hashing it.
3. Call `storage_deposit({ account_id: message_account_id })` with attached deposit of `native_fee + required_storage_balance`. This succeeds with no restrictions.
4. Call `ft_transfer_call` on the token contract with `receiver_id: bridge` and `msg` containing `InitTransferMsg { native_token_fee: native_fee, ... }`.
5. Inside `init_transfer`, `try_to_transfer_balance_from_message_account` finds the pre-funded message account, satisfies all balance checks, and returns `Ok`. The `||` short-circuits. The `NativeFeeRestricted` check is never reached. `init_transfer_internal` is called with `native_fee > 0`, violating the role restriction.

### Citations

**File:** near/omni-bridge/src/lib.rs (L566-581)
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
```

**File:** near/omni-bridge/src/lib.rs (L635-645)
```rust
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
```

**File:** near/omni-bridge/src/storage.rs (L140-169)
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

**File:** near/omni-types/src/lib.rs (L599-621)
```rust
#[near(serializers=[borsh])]
#[derive(Debug, Clone)]
pub struct TransferMessageStorageAccount {
    pub token: OmniAddress,
    pub amount: U128,
    pub recipient: OmniAddress,
    pub fee: Fee,
    pub sender: OmniAddress,
    pub msg: String,
}

impl TransferMessageStorageAccount {
    #[allow(clippy::missing_panics_doc)]
    pub fn id(&self, external_id: Option<String>) -> AccountId {
        let mut bytes = borsh::to_vec(self).unwrap();
        if let Some(external_id) = external_id {
            bytes.extend_from_slice(external_id.as_bytes());
        }
        let hash = utils::sha256(&bytes);
        let implicit_account_id = hex::encode(hash);
        AccountId::try_from(implicit_account_id).unwrap()
    }
}
```
