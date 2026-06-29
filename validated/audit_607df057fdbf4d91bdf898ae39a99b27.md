### Title
`NativeFeeRestricted` Role Bypass via Yield/Resume Path — (`near/omni-bridge/src/lib.rs`)

### Summary

The `NativeFeeRestricted` role is enforced only in one branch of `init_transfer`'s storage-routing logic. When the yield/resume path is taken, `init_transfer_resume` re-enters `init_transfer_internal` without re-checking the role, allowing a restricted account to embed a non-zero `native_fee` in a pending transfer and have it accepted.

### Finding Description

In `init_transfer`, the storage-routing decision is:

```rust
if self.try_to_transfer_balance_from_message_account(...).is_ok()
    || (self.has_storage_balance(...) && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
{
    // direct path — role IS checked
} else {
    // yield path — role is NOT checked
}
``` [1](#0-0) 

When a `NativeFeeRestricted` account submits a transfer with `native_fee > 0` and has sufficient storage balance, neither branch is satisfied (the role check in the second branch fails), so execution falls into the yield path. The yielded callback is `init_transfer_resume`:

```rust
pub fn init_transfer_resume(...) -> U128 {
    self.remove_promise(&message_storage_account_id);
    if let Err(err) = self.try_to_transfer_balance_from_message_account(
        &message_storage_account_id,
        NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
        &storage_owner,
        ...
    ) { ... }
    self.init_transfer_internal(transfer_message, storage_owner)
}
``` [2](#0-1) 

`init_transfer_resume` contains **no** `NativeFeeRestricted` role check. Once the attacker (or any third party) deposits to the virtual message-storage account, the resume fires and `init_transfer_internal` stores the transfer message — including the non-zero `native_fee` — unconditionally.

A second, even simpler bypass exists: if the attacker pre-funds the message-storage account before calling `ft_transfer_call`, the very first branch (`try_to_transfer_balance_from_message_account.is_ok()`) succeeds and the role check in the second branch is never evaluated. [3](#0-2) 

The `NativeFeeRestricted` role is defined as a first-class access-control role: [4](#0-3) 

### Impact Explanation

A `NativeFeeRestricted` account can embed an arbitrary `native_fee` in a cross-chain transfer. The native fee is deducted from the sender's storage balance and credited to the relayer at `sign_transfer` time. This constitutes a **role bypass**: the protocol's access-control invariant — that `NativeFeeRestricted` accounts cannot set native fees — is violated through a reachable, unprivileged code path. The inconsistency is structural: the same restriction is enforced in the direct path but absent in the resume path and the message-account pre-funding path, mirroring the external report's pattern of a state condition (reporter invalidated / yield path taken) silently removing a guard.

### Likelihood Explanation

Any account that has been assigned the `NativeFeeRestricted` role can trigger this. The attacker only needs to call `ft_transfer_call` with a non-zero `native_token_fee` and then deposit to the predicted virtual storage account. Both operations are standard, permissionless bridge interactions. No privileged access beyond holding the restricted role is required.

### Recommendation

Move the `NativeFeeRestricted` role check out of the storage-routing branch and into a standalone guard at the top of `init_transfer`, before any branching occurs:

```rust
require!(
    init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
    BridgeError::NativeFeeNotAllowed.as_ref()
);
```

This ensures the restriction is enforced regardless of which storage-payment path is taken, eliminating the inconsistency between the direct path, the pre-funded message-account path, and the yield/resume path.

### Proof of Concept

1. Admin grants `NativeFeeRestricted` to `attacker.near`.
2. `attacker.near` calls `ft_transfer_call` on a registered token with `msg = InitTransferMsg { native_token_fee: U128(1_000_000_000_000_000_000_000_000), fee: U128(0), recipient: "eth:0x...", ... }`.
3. Because `attacker.near` has the role and `native_fee > 0`, the second branch of the OR fails; `try_to_transfer_balance_from_message_account` also fails (no message account yet) → execution enters the yield path.
4. `attacker.near` calls `storage_deposit` on the bridge contract with `account_id = <predicted virtual account id>`, depositing enough to cover storage + native fee.
5. The yield fires; `init_transfer_resume` runs, `try_to_transfer_balance_from_message_account` now succeeds, and `init_transfer_internal` stores the transfer with `native_fee = 1e24 yoctoNEAR`.
6. A relayer calls `sign_transfer`; the native fee is paid out, bypassing the `NativeFeeRestricted` restriction entirely. [5](#0-4) [6](#0-5)

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

**File:** near/omni-bridge/src/lib.rs (L566-618)
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
