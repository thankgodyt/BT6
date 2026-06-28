### Title
`NativeFeeRestricted` Role Bypass via Yield/Resume Path in `init_transfer` — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function in the NEAR omni-bridge contract enforces the `NativeFeeRestricted` role check only in one of two execution branches. The parallel yield/resume path (`init_transfer_resume`) performs no such check, allowing a user who has been assigned `NativeFeeRestricted` to bypass the restriction and successfully submit a transfer with a non-zero `native_token_fee`.

---

### Finding Description

The NEAR omni-bridge contract defines a `NativeFeeRestricted` role intended to prevent certain accounts from setting a non-zero native fee when initiating a cross-chain transfer. [1](#0-0) 

The `init_transfer` function (called from `ft_on_transfer`) contains a branching condition that decides whether to execute the transfer immediately or yield execution until storage is available: [2](#0-1) 

The `NativeFeeRestricted` check appears **only** in the second sub-condition of the OR expression (line 580):

```rust
&& (init_transfer_msg.native_token_fee.0 == 0
    || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()))
```

The **first** sub-condition — `try_to_transfer_balance_from_message_account(...).is_ok()` — has **no role check at all**. If the message storage account has been pre-funded (by anyone, including the restricted user), this branch succeeds and the transfer proceeds immediately, completely skipping the `NativeFeeRestricted` guard.

Furthermore, the `init_transfer_resume` callback — which handles the yield/resume path — also contains **no `NativeFeeRestricted` check**: [3](#0-2) 

The `TransferMessage` stored in the yield already contains the attacker-controlled non-zero `native_fee`. When `init_transfer_resume` fires, it calls `try_to_transfer_balance_from_message_account` and then `init_transfer_internal` without ever verifying the role.

---

### Impact Explanation

A user assigned `NativeFeeRestricted` can bypass the restriction and submit a cross-chain transfer with a non-zero `native_token_fee`. This is a direct role bypass: the protocol's access-control mechanism for native fee usage is rendered ineffective. The `NativeFeeRestricted` role is a protocol-level enforcement control; its bypass undermines the protocol's ability to restrict specific accounts from using native NEAR fees to incentivize relayers, which may have compliance, economic, or operational implications depending on why the restriction was applied.

---

### Likelihood Explanation

The attack is fully self-contained and requires no privileged access beyond holding the `NativeFeeRestricted` role (which is the exact condition the restriction is meant to govern). The attacker needs only to:
1. Compute the deterministic message storage account ID from their transfer parameters.
2. Pre-fund it via `storage_deposit` before or after calling `ft_transfer_call`.

Both the direct bypass (pre-fund before calling) and the yield bypass (trigger yield, then fund) are reachable by any unprivileged bridge user who has been assigned the role.

---

### Recommendation

Add the `NativeFeeRestricted` check to **both** execution paths:

1. **In `init_transfer`**: Guard the first branch (`try_to_transfer_balance_from_message_account`) with the same role check, or restructure the condition so the role check is evaluated unconditionally before either branch is taken.

2. **In `init_transfer_resume`**: Add an explicit check before calling `init_transfer_internal`:

```rust
if transfer_message.fee.native_fee.0 != 0
    && self.acl_has_role(Role::NativeFeeRestricted.into(), storage_owner.clone())
{
    env::log_str("NativeFeeRestricted: native fee not allowed");
    return transfer_message.amount;
}
```

---

### Proof of Concept

**Yield-path bypass:**

1. Admin grants `NativeFeeRestricted` to `restricted_user`.
2. `restricted_user` calls `ft_transfer_call` on the token contract with `native_token_fee > 0` and a recipient on a foreign chain.
3. Inside `init_transfer`:
   - `try_to_transfer_balance_from_message_account` returns `Err` (message account is empty).
   - The second branch fails because `NativeFeeRestricted` is set and `native_fee != 0`.
   - Execution falls to the `else` branch: `promise_yield_create("init_transfer_resume", ...)` is called with the full `TransferMessage` (including non-zero `native_fee`) serialized into the yield arguments.
4. `restricted_user` calls `storage_deposit` on the message storage account ID (deterministically computable from transfer parameters) with sufficient NEAR.
5. The yield fires: `init_transfer_resume` is called.
6. `init_transfer_resume` calls `try_to_transfer_balance_from_message_account` — succeeds (account is now funded).
7. `init_transfer_internal` is called with the original `TransferMessage` containing non-zero `native_fee`.
8. An `InitTransferEvent` is emitted with `native_fee > 0`, bypassing the restriction entirely. [4](#0-3) [5](#0-4)

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
