### Title
`NativeFeeRestricted` Role Bypass via Pre-funded Message Storage Account or Yield/Resume Path - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `NativeFeeRestricted` role is intended to prevent certain accounts from attaching a native NEAR fee to their bridge transfers. However, the restriction check in `init_transfer` is only applied in one of two execution branches, and is entirely absent from the `init_transfer_resume` callback. A restricted user can bypass the restriction by either pre-funding the deterministic message storage account before calling `ft_transfer_call`, or by triggering the yield/resume path where no role check is performed.

### Finding Description

In `near/omni-bridge/src/lib.rs`, the `init_transfer` function contains the following branching logic:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // Branch 1
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(...)                 // Branch 2
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
{
    // proceed with transfer
} else {
    // yield execution
}
``` [1](#0-0) 

The `NativeFeeRestricted` check (`acl_has_role`) only appears in **Branch 2**. **Branch 1** — which succeeds when the `message_storage_account_id` virtual account has been pre-funded — skips the restriction check entirely.

The `message_storage_account_id` is a deterministic, publicly computable account ID derived from the transfer parameters (token, amount, recipient, fee, sender, msg, external_id): [2](#0-1) 

Because this account ID is deterministic and `storage_deposit` is permissionless, a restricted user can pre-compute and pre-fund it before calling `ft_transfer_call`.

**Second bypass path — `init_transfer_resume`:** Even without pre-funding, a `NativeFeeRestricted` user with `native_fee > 0` will always fall into the yield branch (Branch 1 fails because the message account is not yet funded; Branch 2 fails because the role check blocks them). The yielded transfer is then resumed by `init_transfer_resume`:

```rust
pub fn init_transfer_resume(
    &mut self,
    transfer_message: TransferMessage,
    message_storage_account_id: AccountId,
    storage_owner: AccountId,
    #[callback_result] response: Result<(), PromiseError>,
) -> U128 {
    self.remove_promise(&message_storage_account_id);
    ...
    if let Err(err) = self.try_to_transfer_balance_from_message_account(...) {
        ...
        return transfer_message.amount;
    }
    self.init_transfer_internal(transfer_message, storage_owner)
}
``` [3](#0-2) 

`init_transfer_resume` contains **no `NativeFeeRestricted` check**. Once the restricted user (or any third party) deposits to the message storage account, the yield resumes and the transfer proceeds with the native fee intact.

### Impact Explanation

A user assigned the `NativeFeeRestricted` role can fully bypass the restriction and attach an arbitrary native NEAR fee to their bridge transfer. This undermines the protocol's access-control enforcement: the role is rendered ineffective. The native fee is paid from the user's own NEAR balance to the relayer, but the governance/compliance intent of the restriction is defeated. This is a role bypass as defined in the allowed impact scope.

### Likelihood Explanation

The bypass is straightforward to execute. The `message_storage_account_id` is deterministic and computable off-chain from public parameters. The `storage_deposit` function is permissionless. Any `NativeFeeRestricted` user who is aware of the mechanism can exploit it in a single transaction sequence. Likelihood is **Medium** (requires knowledge of the mechanism, but no privileged access or complex setup).

### Recommendation

Add the `NativeFeeRestricted` check in `init_transfer_resume` before calling `init_transfer_internal`, mirroring the check in `init_transfer`. Additionally, ensure Branch 1 of `init_transfer` also enforces the restriction when `native_token_fee > 0`:

```rust
// In init_transfer_resume, before init_transfer_internal:
if transfer_message.fee.native_fee.0 > 0
    && self.acl_has_role(Role::NativeFeeRestricted.into(), storage_owner.clone())
{
    env::log_str("NativeFeeRestricted: native fee not allowed");
    return transfer_message.amount;
}
```

Similarly, in Branch 1 of `init_transfer`, after `try_to_transfer_balance_from_message_account` succeeds, verify the restriction before proceeding.

### Proof of Concept

**Path 1 — Pre-funded message account:**
1. Admin grants `NativeFeeRestricted` to `alice.near`.
2. `alice.near` computes `message_storage_account_id` from her intended transfer parameters (all fields are known before the call).
3. `alice.near` calls `storage_deposit(account_id = message_storage_account_id)` with enough NEAR to cover `native_fee + required_storage_balance`.
4. `alice.near` calls `ft_transfer_call` with `native_token_fee > 0`.
5. `try_to_transfer_balance_from_message_account` succeeds (Branch 1) → restriction check is skipped → transfer proceeds with native fee.

**Path 2 — Yield/resume:**
1. Admin grants `NativeFeeRestricted` to `alice.near`.
2. `alice.near` calls `ft_transfer_call` with `native_token_fee > 0` and minimal storage balance (only account registration minimum).
3. Both branches fail → execution yields on `message_storage_account_id`.
4. `alice.near` calls `storage_deposit(account_id = message_storage_account_id)` with sufficient NEAR.
5. `init_transfer_resume` is triggered — no restriction check — `init_transfer_internal` is called with the native fee intact. [4](#0-3) [3](#0-2) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L565-618)
```rust
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
        }
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

**File:** near/omni-types/src/lib.rs (L589-620)
```rust
    pub fn calculate_storage_account_id(&self, external_id: Option<String>) -> AccountId {
        TransferMessageStorageAccount::from(self.clone()).id(external_id)
    }

    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
}

// Used to calculate virtual account ID that can be used to deposit storage required for the message
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
