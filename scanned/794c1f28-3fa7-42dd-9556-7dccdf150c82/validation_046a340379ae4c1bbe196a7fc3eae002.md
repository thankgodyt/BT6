### Title
`NativeFeeRestricted` Role Bypass via Message-Account Pre-Deposit in `init_transfer` — (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR bridge contract enforces a `NativeFeeRestricted` role to prevent designated accounts from attaching a non-zero `native_token_fee` to outbound transfers. The enforcement check is placed only inside one branch of an OR-guarded condition in `init_transfer`. The other branch — the "message account" path — performs no role check at all. An account bearing the `NativeFeeRestricted` role can pre-deposit the native fee to the deterministic message-storage virtual account and trigger the unchecked branch, bypassing the restriction entirely.

### Finding Description

`init_transfer` (called from `ft_on_transfer`) decides whether to proceed immediately or yield via the following compound condition:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // Branch 1 – no role check
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(...)                // Branch 2 – role check here
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
{
    self.init_transfer_internal(transfer_message, signer_id)
}
``` [1](#0-0) 

The `NativeFeeRestricted` role check (`!self.acl_has_role(...)`) lives exclusively in Branch 2. Branch 1 (`try_to_transfer_balance_from_message_account`) succeeds whenever the message-storage virtual account already holds sufficient balance, and it performs **no role check**. Because Rust's `||` short-circuits, a successful Branch 1 causes Branch 2 — and its role guard — to be skipped entirely.

The message-storage account ID is derived deterministically from the transfer parameters the attacker controls:

```rust
pub struct TransferMessageStorageAccount {
    pub token: OmniAddress,
    pub amount: U128,
    pub recipient: OmniAddress,
    pub fee: Fee,
    pub sender: OmniAddress,
    pub msg: String,
}
``` [2](#0-1) 

`origin_nonce` is not part of the storage account ID, so the attacker can compute the virtual account address before submitting the transfer.

`try_to_transfer_balance_from_message_account` itself only checks that the message account has enough balance to cover the native fee and that the signer has enough for storage — no role check: [3](#0-2) 

### Impact Explanation

A `NativeFeeRestricted` account can attach an arbitrary non-zero `native_token_fee` to any outbound transfer despite the role restriction. The native fee is minted or transferred to the relayer who signs the transfer. This constitutes a **role bypass**: the protocol's access-control invariant — that `NativeFeeRestricted` accounts cannot use the native fee mechanism — is violated by any holder of that role. The bypass is fully self-funded (the attacker pays from their own deposited balance), so there is no direct theft of protocol funds, but the role restriction is rendered ineffective.

### Likelihood Explanation

The attacker must already hold the `NativeFeeRestricted` role (i.e., the protocol has already flagged them). Given that role, the bypass requires only two public calls: `storage_deposit` to the pre-computed virtual account, then `ft_transfer_call` with a non-zero `native_token_fee`. Both calls are permissionless and require no privileged access beyond the role itself. The message-storage account ID is fully predictable from attacker-controlled inputs.

### Recommendation

Move the `NativeFeeRestricted` check to a position that is evaluated unconditionally — before the OR branch — so that it cannot be bypassed regardless of which storage path is taken:

```rust
if init_transfer_msg.native_token_fee.0 != 0 {
    require!(
        !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
        BridgeError::NativeFeeRestricted.as_ref()
    );
}

if self.try_to_transfer_balance_from_message_account(...).is_ok()
    || self.has_storage_balance(...)
{
    self.init_transfer_internal(transfer_message, signer_id)
}
```

### Proof of Concept

1. Admin grants `NativeFeeRestricted` to `attacker.near`.
2. Attacker constructs the planned `InitTransferMsg` (token, amount, recipient, fee, msg).
3. Attacker calls `required_balance_for_init_transfer_message` (or computes it) to get the storage cost.
4. Attacker computes `message_storage_account_id` from `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }`.
5. Attacker calls `storage_deposit(account_id = message_storage_account_id)` depositing `native_token_fee + required_storage`.
6. Attacker calls `ft_transfer_call` on the token contract with `receiver_id = locker`, `amount`, and `msg = InitTransferMsg { native_token_fee: <non-zero>, ... }`.
7. Inside `ft_on_transfer` → `init_transfer`, Branch 1 (`try_to_transfer_balance_from_message_account`) succeeds because the virtual account is funded. The OR short-circuits; Branch 2 and its `NativeFeeRestricted` check are never evaluated.
8. `init_transfer_internal` is called with a non-zero `native_fee` in the stored `TransferMessage`, and the relayer later receives the native fee — despite the attacker being `NativeFeeRestricted`. [1](#0-0) [3](#0-2)

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

**File:** near/omni-types/src/lib.rs (L599-608)
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
