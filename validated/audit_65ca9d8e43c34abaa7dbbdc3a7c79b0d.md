Audit Report

## Title
`NativeFeeRestricted` Role Bypass via Message-Account Pre-funding in `init_transfer` — (File: near/omni-bridge/src/lib.rs)

## Summary

The `NativeFeeRestricted` role check in `init_transfer` is placed exclusively inside Branch B of a short-circuit OR condition. Branch A — `try_to_transfer_balance_from_message_account` — carries no role check. Because the message storage account ID is fully deterministic and computable before the transfer is submitted, a `NativeFeeRestricted` user can pre-fund that virtual account via `storage_deposit`, force Branch A to return `Ok`, and reach `init_transfer_internal` with a non-zero `native_token_fee` without the role ever being consulted. The same gap exists in `init_transfer_resume`.

## Finding Description

In `init_transfer` (lines 566–584), the branching logic is:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // Branch A — no role check
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(&signer_id, ...)
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
    // ↑ Branch B — role check lives here only
{
    self.init_transfer_internal(transfer_message, signer_id)
``` [1](#0-0) 

`try_to_transfer_balance_from_message_account` (storage.rs lines 260–290) returns `Ok(())` when the virtual message account is registered in `accounts_balances` and holds enough balance to cover `native_fee` plus storage. It performs no role check. [2](#0-1) 

`storage_deposit` (storage.rs lines 141–169) accepts an arbitrary `account_id` parameter — any caller can register and fund any account ID, including the pre-computed virtual message account. [3](#0-2) 

The message storage account ID is computed deterministically from `TransferMessageStorageAccount::id()`, which hashes token, amount, recipient, fee, sender, and msg — nonces are explicitly excluded — so the ID is computable off-chain before the transfer is submitted. [4](#0-3) 

The same gap exists in `init_transfer_resume` (lines 635–645): it calls `try_to_transfer_balance_from_message_account` and, on success, calls `init_transfer_internal` with no role check, allowing a `NativeFeeRestricted` user to trigger the bypass via the yield/resume path as well. [5](#0-4) 

`init_transfer_internal` contains no `NativeFeeRestricted` check of its own. [6](#0-5) 

## Impact Explanation

`NativeFeeRestricted` is a compliance role that prevents designated accounts from attaching a native NEAR fee to outbound transfers. [7](#0-6) 

By bypassing this restriction, a `NativeFeeRestricted` user can attach an arbitrary native NEAR fee to their transfer, incentivizing relayers to process it and circumventing the compliance control entirely. This is a concrete **role bypass** that lets the attacker execute a bridge action — attaching a native fee — that the protocol has explicitly forbidden for their account. This matches the allowed critical impact: "authorization bypass, role bypass… that lets an attacker execute bridge… actions."

## Likelihood Explanation

Exploitation requires only two sequential on-chain calls from any account that has been assigned the `NativeFeeRestricted` role:

1. `storage_deposit` targeting the pre-computed virtual account ID (computable off-chain, no nonce dependency).
2. `ft_transfer_call` with a non-zero `native_token_fee`.

No privileged access, leaked keys, or external dependency is required beyond holding the `NativeFeeRestricted` role itself. The bypass is fully self-contained and repeatable.

## Recommendation

Move the `NativeFeeRestricted` role check to an unconditional position evaluated before the branching logic, whenever `native_token_fee > 0`:

```rust
if init_transfer_msg.native_token_fee.0 > 0 {
    require!(
        !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
        BridgeError::OperationNotAllowed.as_ref()
    );
}
```

Apply the same guard at the top of `init_transfer_resume` before calling `try_to_transfer_balance_from_message_account`.

## Proof of Concept

```
1. Admin grants NativeFeeRestricted role to attacker.near.

2. Attacker computes the virtual message storage account ID off-chain:
   TransferMessageStorageAccount {
       token:     Near("token.near"),
       amount:    U128(1_000),
       recipient: Eth(0xDEAD...),
       fee:       Fee { fee: U128(0), native_fee: U128(1_000_000_000_000_000_000_000_000) },
       sender:    Near("attacker.near"),
       msg:       "",
   }.id(None)
   → deterministic hex account ID (e.g., "a3f7...c2d1")

3. Attacker calls:
   bridge.storage_deposit({ account_id: "a3f7...c2d1" })
   with deposit = native_fee + required_storage_balance
   → virtual account is now registered in accounts_balances

4. Attacker calls:
   token.ft_transfer_call({
       receiver_id: "bridge.near",
       amount: "1000",
       msg: InitTransferMsg { native_token_fee: "1000000000000000000000000", ... }
   })

5. Inside init_transfer:
   - try_to_transfer_balance_from_message_account("a3f7...c2d1", ...) → Ok(())
     (message account is registered and funded; no role check performed)
   - Short-circuit OR: Branch B is never evaluated
   - init_transfer_internal is called with native_fee = 1 NEAR

6. Transfer is registered with a non-zero native fee.
   NativeFeeRestricted check was never reached.
   Relayers are now incentivized to process the restricted user's transfer.

Verification: parse the InitTransferEvent log and assert transfer_message.fee.native_fee > 0
for an account holding the NativeFeeRestricted role.
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

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** near/omni-bridge/src/storage.rs (L141-169)
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

**File:** near/omni-types/src/lib.rs (L610-621)
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
}
```
