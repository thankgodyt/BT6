Audit Report

## Title
`NativeFeeRestricted` Role Bypass via Yield Path in `init_transfer_resume` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `NativeFeeRestricted` role check in `init_transfer` is embedded only in the branch condition that selects the direct execution path. When the condition evaluates to `false` for a restricted account with `native_token_fee > 0`, execution falls into the NEAR yield path, serialising the transfer message (including the non-zero native fee) as yield arguments. The resume callback `init_transfer_resume` contains no `NativeFeeRestricted` check and calls `init_transfer_internal` unconditionally, allowing the restricted account to complete the transfer with the non-zero native fee intact.

## Finding Description
In `init_transfer`, the guard is:

```rust
if self.try_to_transfer_balance_from_message_account(...).is_ok()
|| (self.has_storage_balance(&signer_id, ...)
    && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
``` [1](#0-0) 

For a `NativeFeeRestricted` account with `native_token_fee > 0` and no pre-funded message account, both clauses are `false`, so the yield path is taken and the full `TransferMessage` (with `native_fee > 0`) is stored as yield arguments. [2](#0-1) 

`init_transfer_resume` calls `init_transfer_internal` with no role check: [3](#0-2) 

The yield is resumed via `storage_deposit`: when anyone calls `storage_deposit` with `account_id = <message_storage_account_id>`, the contract calls `resume_promise` which invokes `env::promise_yield_resume`. [4](#0-3) 

The message storage account ID is deterministically derived from `(token, amount, recipient, fee, sender, msg)` — nonces are excluded — so it is fully predictable before the transfer is submitted. [5](#0-4) 

Upon `claim_fee`, `send_fee_internal` transfers NEAR or mints native tokens to the relayer when `native_fee > 0`. [6](#0-5) 

## Impact Explanation
This is a concrete role bypass: a DAO-assigned `NativeFeeRestricted` restriction is rendered completely ineffective. The bypass has a direct on-chain financial effect — native NEAR tokens are transferred, or native tokens are minted to a relayer of the attacker's choice via `send_fee_internal`. This matches the allowed critical impact class: *"role bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions"* and *"fee mis-accounting that changes user or protocol balances."*

## Likelihood Explanation
Any account holding the `NativeFeeRestricted` role can trigger this without any additional privileges. The attacker simply needs to not pre-fund their bridge storage balance (or ensure the message account does not yet exist), submit `ft_transfer_call` with `native_token_fee > 0`, compute the deterministic message storage account ID, and call `storage_deposit` on that account. The exploit is repeatable for every transfer.

## Recommendation
Add the `NativeFeeRestricted` check inside `init_transfer_resume` before calling `init_transfer_internal`, mirroring the guard in the direct path:

```rust
if transfer_message.fee.native_fee.0 != 0
    && self.acl_has_role(Role::NativeFeeRestricted.into(), storage_owner.clone())
{
    env::log_str("NativeFeeRestricted: native fee not allowed");
    return transfer_message.amount;
}
self.init_transfer_internal(transfer_message, storage_owner)
``` [7](#0-6) 

## Proof of Concept
1. DAO grants `NativeFeeRestricted` to `attacker.near`.
2. `attacker.near` calls `ft_transfer_call` on a registered token with `msg` containing `native_token_fee = 1_000_000_000_000_000_000_000_000` (1 NEAR). The attacker has no pre-funded bridge storage balance and the message account does not exist.
3. `init_transfer` evaluates: `try_to_transfer_balance_from_message_account` returns `Err(MessageAccountNotRegistered)`; `has_storage_balance` is `false` (or `NativeFeeRestricted && native_fee != 0` makes the second clause `false`). Condition is `false` → yield path taken. `TransferMessage` with `native_fee = 1 NEAR` is serialised as yield arguments.
4. Attacker pre-computes the deterministic message storage account ID from `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }`.
5. Attacker calls `storage_deposit` on the bridge contract with `account_id = <computed message account>`, depositing enough NEAR to cover storage + native fee. `storage_deposit` calls `resume_promise` → `env::promise_yield_resume` fires.
6. `init_transfer_resume` runs: `try_to_transfer_balance_from_message_account` succeeds (message account now funded), then `init_transfer_internal` is called — no role check performed. Transfer is registered with `native_fee = 1 NEAR`.
7. A relayer calls `sign_transfer` then `claim_fee`; `send_fee_internal` transfers 1 NEAR to the relayer. The `NativeFeeRestricted` restriction has been fully bypassed.

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

**File:** near/omni-bridge/src/lib.rs (L585-617)
```rust
        } else {
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

**File:** near/omni-bridge/src/lib.rs (L2656-2673)
```rust
        if transfer_message.fee.native_fee.0 != 0 {
            let origin_chain = transfer_message.origin_transfer_id.as_ref().map_or_else(
                || transfer_message.get_origin_chain(),
                |origin_transfer_id| origin_transfer_id.origin_chain,
            );

            if origin_chain.is_utxo_chain() {
                env::panic_str(BridgeError::NativeFeeForUtxoChain.to_string().as_str())
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```

**File:** near/omni-bridge/src/storage.rs (L141-184)
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
