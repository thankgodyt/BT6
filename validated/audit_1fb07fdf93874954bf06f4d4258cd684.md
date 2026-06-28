### Title
`NativeFeeRestricted` Role Bypass via Pre-Funded Message Storage Account - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `NativeFeeRestricted` role is intended to prevent certain accounts from setting a non-zero `native_token_fee` on bridge transfers. However, the restriction check is only applied in one branch of a two-branch OR condition inside `init_transfer`. An account holding the `NativeFeeRestricted` role can bypass the check entirely by pre-depositing funds into the deterministic message storage account before calling `ft_transfer_call`, causing the unchecked branch to execute and the restriction to be silently skipped.

### Finding Description

In `near/omni-bridge/src/lib.rs`, the `init_transfer` function decides whether to proceed immediately or yield based on the following condition:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // Branch 1 – NO restriction check
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(                    // Branch 2 – restriction IS checked
        &signer_id,
        required_storage_balance.saturating_add(NearToken::from_yoctonear(
            init_transfer_msg.native_token_fee.0,
        )),
    ) && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
``` [1](#0-0) 

Branch 1 (`try_to_transfer_balance_from_message_account`) contains **no** `NativeFeeRestricted` check. It only verifies that the virtual message storage account has a sufficient balance and that the signer has a registered storage account. If Branch 1 succeeds, the OR short-circuits and Branch 2 (which contains the role check) is never evaluated.

The `message_storage_account_id` is derived deterministically from the transfer message fields (token, amount, recipient, fee, sender, msg, external_id): [2](#0-1) 

Because this ID is fully predictable before the transfer is submitted, a restricted account can:

1. Compute `message_storage_account_id` off-chain using the intended transfer parameters.
2. Call `storage_deposit` with `account_id = message_storage_account_id`, depositing at least `native_token_fee` yoctoNEAR.
3. Call `ft_transfer_call` with a non-zero `native_token_fee`.
4. Inside `init_transfer`, `try_to_transfer_balance_from_message_account` succeeds (the message account is funded), Branch 1 returns `Ok`, the OR short-circuits, and the `NativeFeeRestricted` check in Branch 2 is never reached.
5. `init_transfer_internal` is called with the non-zero native fee accepted. [3](#0-2) 

The `NativeFeeRestricted` role definition confirms this is an intentional protocol-level restriction: [4](#0-3) 

### Impact Explanation

A `NativeFeeRestricted` account can set an arbitrary non-zero `native_token_fee` on any outbound NEAR transfer, bypassing the protocol's explicit role-based restriction. This is a role bypass that lets a restricted actor perform an action the protocol explicitly prohibits. The native fee is paid from the attacker's own storage balance to the relayer, so the attacker can selectively incentivize relayers with NEAR tokens in violation of the restriction policy. If the `NativeFeeRestricted` role is used to enforce compliance, economic, or anti-abuse controls, those controls are rendered ineffective.

### Likelihood Explanation

Exploitation requires only standard, publicly available bridge interactions: `storage_deposit` (to fund the message account) followed by `ft_transfer_call` (to initiate the transfer). No privileged access, leaked keys, or external dependencies are needed. The message storage account ID is deterministic and computable off-chain. Any account that has been assigned the `NativeFeeRestricted` role and is motivated to bypass it can do so trivially.

### Recommendation

Move the `NativeFeeRestricted` check outside and before the two-branch OR condition so it applies regardless of which storage-payment path is taken:

```rust
// Enforce restriction before any storage-path selection
if init_transfer_msg.native_token_fee.0 > 0 {
    require!(
        !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
        BridgeError::NativeFeeRestricted.as_ref()
    );
}

if self.try_to_transfer_balance_from_message_account(...).is_ok()
    || (self.has_storage_balance(...) && init_transfer_msg.native_token_fee.0 == 0)
{
    ...
}
```

This ensures the role restriction is enforced unconditionally, regardless of whether the message-account pre-funding path or the direct storage-balance path is used.

### Proof of Concept

```
// Precondition: attacker has NativeFeeRestricted role assigned by DAO.

// Step 1 – compute the deterministic message storage account ID off-chain
//   using the same fields TransferMessage::calculate_storage_account_id uses.

// Step 2 – pre-fund the message account
attacker.call(bridge_contract, "storage_deposit")
    .args_json({"account_id": message_storage_account_id})
    .deposit(native_fee_amount + required_storage_balance)

// Step 3 – also register attacker's own account (needed by try_to_transfer_balance_from_message_account)
attacker.call(bridge_contract, "storage_deposit")
    .args_json({"account_id": attacker.id()})
    .deposit(required_balance_for_account)

// Step 4 – initiate transfer with non-zero native fee
attacker.call(token_contract, "ft_transfer_call")
    .args_json({
        "receiver_id": bridge_contract,
        "amount": transfer_amount,
        "msg": {"InitTransfer": {"native_token_fee": native_fee_amount, "fee": 0, "recipient": eth_address}}
    })
    .deposit(1)

// Expected (broken) result:
//   try_to_transfer_balance_from_message_account succeeds → OR short-circuits
//   NativeFeeRestricted check is never evaluated
//   Transfer is stored with non-zero native_fee
//   Relayer receives NEAR native fee despite attacker being restricted
```

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

**File:** near/omni-bridge/src/lib.rs (L562-563)
```rust
        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));
```

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
