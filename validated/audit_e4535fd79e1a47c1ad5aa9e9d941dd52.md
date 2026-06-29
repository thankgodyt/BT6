Audit Report

## Title
`NativeFeeRestricted` Role Bypass via Message-Account Pre-Deposit in `init_transfer` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `NativeFeeRestricted` role check in `init_transfer` is placed exclusively inside Branch 2 of a short-circuit `||` condition. Branch 1 (`try_to_transfer_balance_from_message_account`) performs no role check and, when it succeeds, causes Rust's `||` to skip Branch 2 entirely. Because the message-storage virtual account ID is deterministically derived from attacker-controlled inputs (excluding `origin_nonce`), a `NativeFeeRestricted` account can pre-fund that virtual account and trigger Branch 1, bypassing the restriction and attaching an arbitrary non-zero `native_token_fee` to any outbound transfer.

## Finding Description
In `near/omni-bridge/src/lib.rs` at lines 566–584, `init_transfer` evaluates:

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
``` [1](#0-0) 

`try_to_transfer_balance_from_message_account` only verifies that the message account holds enough balance to cover `native_fee` and that the signer has enough for storage — no role check is performed anywhere inside it. [2](#0-1) 

The message-storage account ID is computed from `TransferMessageStorageAccount`, which does **not** include `origin_nonce`, making it fully predictable from attacker-controlled fields: [3](#0-2) 

Exploit flow:
1. Admin grants `NativeFeeRestricted` to `attacker.near`.
2. Attacker constructs the planned `InitTransferMsg` (token, amount, recipient, fee, msg).
3. Attacker computes `message_storage_account_id` from `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }`.
4. Attacker calls `storage_deposit(account_id = message_storage_account_id)` depositing `native_token_fee + required_storage`.
5. Attacker calls `ft_transfer_call` with `native_token_fee: <non-zero>`.
6. Inside `ft_on_transfer → init_transfer`, Branch 1 succeeds (virtual account is funded); `||` short-circuits; Branch 2 and its `NativeFeeRestricted` check are never evaluated.
7. `init_transfer_internal` is called with a non-zero `native_fee` in the stored `TransferMessage`. [4](#0-3) 

## Impact Explanation
This is a confirmed role bypass: the protocol's access-control invariant — that `NativeFeeRestricted` accounts cannot use the native fee mechanism — is violated. The attacker executes a bridge action (outbound transfer with non-zero `native_token_fee`) that the role is specifically designed to prohibit. This matches the allowed critical impact class: *"role bypass… that lets an attacker execute bridge… actions."* The bypass is self-funded (attacker pays from their own deposited balance), so there is no direct theft of protocol funds, but the role restriction is rendered entirely ineffective.

## Likelihood Explanation
The attacker must already hold the `NativeFeeRestricted` role (i.e., the protocol has flagged them). Given that precondition, the bypass requires only two permissionless public calls — `storage_deposit` to the pre-computed virtual account, then `ft_transfer_call` with a non-zero `native_token_fee`. The message-storage account ID is fully predictable from attacker-controlled inputs. No privileged access, victim interaction, or external dependency is required beyond the role itself. The attack is repeatable for every transfer the attacker initiates.

## Recommendation
Move the `NativeFeeRestricted` check to an unconditional position before the `||` branch, so it is evaluated regardless of which storage path is taken:

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

This ensures the role restriction is enforced regardless of whether the message-account pre-deposit path or the direct storage-balance path is taken.

## Proof of Concept
The existing integration test suite in `near/omni-tests/src/native_fee_role.rs` already sets up the full environment (sandbox, token contract, locker contract, role granting). A minimal reproduction test can be added there:

1. Call `TestEnv::new(...)` to initialize the environment.
2. Grant `NativeFeeRestricted` to `sender_account` via `grant_native_fee_restricted_role`.
3. Compute `message_storage_account_id` from `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }` using `TransferMessageStorageAccount::id(None)`.
4. Call `storage_deposit(account_id = message_storage_account_id)` with `native_fee + required_storage_balance` from `sender_account`.
5. Call `ft_transfer_call` with `native_token_fee: U128(native_fee)` (non-zero) from `sender_account`.
6. Assert that the `InitTransferEvent` log is emitted and `transfer_message.fee.native_fee.0 == native_fee` — confirming the bypass succeeded despite the role restriction. [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L562-584)
```rust
        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
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

**File:** near/omni-tests/src/native_fee_role.rs (L283-368)
```rust
    #[rstest]
    #[tokio::test]
    async fn test_native_fee_restriction(
        mock_token_wasm: Vec<u8>,
        mock_prover_wasm: Vec<u8>,
        locker_wasm: Vec<u8>,
    ) -> anyhow::Result<()> {
        let env = TestEnv::new(mock_token_wasm, mock_prover_wasm, locker_wasm).await?;

        // 1. Test that an account can set a native fee when not restricted
        let transfer_amount = 100;
        let native_fee = NearToken::from_near(1).as_yoctonear();
        let token_fee = 10;

        let transfer_message = env
            .initialize_transfer(
                transfer_amount,
                native_fee,
                token_fee,
                true, // Should succeed
            )
            .await?
            .unwrap();

        assert_eq!(
            transfer_message.fee.native_fee.0, native_fee,
            "Native fee was not set correctly"
        );

        // 2. Grant NativeFeeRestricted role to the sender account
        env.grant_native_fee_restricted_role(env.sender_account.id())
            .await?;

        // 3. Test that the account cannot set a native fee when restricted
        let result = env
            .initialize_transfer(
                transfer_amount,
                native_fee,
                token_fee,
                false, // Should fail
            )
            .await;

        assert!(
            result.is_ok(),
            "Transfer should have failed with the expected error"
        );

        // 4. Test that the account can still transfer with zero native fee
        let transfer_message = env
            .initialize_transfer(
                transfer_amount,
                0, // Zero native fee
                token_fee,
                true, // Should succeed
            )
            .await?
            .unwrap();

        assert_eq!(
            transfer_message.fee.native_fee.0, 0,
            "Native fee should be zero"
        );

        // 5. Revoke the NativeFeeRestricted role
        env.revoke_native_fee_restricted_role(env.sender_account.id())
            .await?;

        // 6. Test that the account can set a native fee after role revocation
        let transfer_message = env
            .initialize_transfer(
                transfer_amount,
                native_fee,
                token_fee,
                true, // Should succeed
            )
            .await?
            .unwrap();

        assert_eq!(
            transfer_message.fee.native_fee.0, native_fee,
            "Native fee was not set correctly after role revocation"
        );

        Ok(())
    }
```
