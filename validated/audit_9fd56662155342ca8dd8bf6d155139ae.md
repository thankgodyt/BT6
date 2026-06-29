### Title
`NativeFeeRestricted` Role Bypass via Yield Path in `init_transfer_resume` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary
The `init_transfer` function enforces the `NativeFeeRestricted` role to block certain accounts from setting a non-zero native fee. This check is entirely absent in `init_transfer_resume`, the yield-resume callback. A restricted account can route around the restriction by triggering the yield path and then depositing storage to the message account, causing `init_transfer_resume` to proceed without any role check.

---

### Finding Description

In `init_transfer`, the direct-execution branch is guarded by:

```rust
|| (self.has_storage_balance(
        &signer_id,
        required_storage_balance.saturating_add(NearToken::from_yoctonear(
            init_transfer_msg.native_token_fee.0,
        )),
    ) && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
```

When a `NativeFeeRestricted` account submits a transfer with `native_token_fee > 0`, this condition evaluates to `false`, so the direct path is blocked and execution falls into the yield path via `env::promise_yield_create("init_transfer_resume", ...)`.

`init_transfer_resume` (the yield callback) is:

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
    if let Err(err) = self.try_to_transfer_balance_from_message_account(
        &message_storage_account_id,
        NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
        &storage_owner,
        self.required_balance_for_init_transfer_message(transfer_message.clone()),
    ) {
        ...
        return transfer_message.amount;
    }

    self.init_transfer_internal(transfer_message, storage_owner)
}
```

There is **no `NativeFeeRestricted` role check here**. Once the attacker deposits NEAR to the message account (via the public `storage_deposit` call), the yield fires, `try_to_transfer_balance_from_message_account` succeeds, and `init_transfer_internal` is called with the non-zero native fee intact — bypassing the restriction entirely. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

A `NativeFeeRestricted` account can circumvent the role restriction and register an outbound transfer with an arbitrary non-zero `native_fee`. The native fee is deducted from the attacker's own deposited NEAR and paid to the relayer upon `sign_transfer` / `claim_fee`. This is a direct **authorization bypass**: the `NativeFeeRestricted` security control — the only mechanism preventing flagged accounts from setting native fees — is rendered ineffective via the yield path. Any account that has been administratively restricted can unilaterally undo that restriction without any privileged access. [3](#0-2) [4](#0-3) 

---

### Likelihood Explanation

The attacker must already hold the `NativeFeeRestricted` role (i.e., they have been explicitly flagged by the DAO). Once flagged, the bypass requires only two standard, permissionless bridge calls: `ft_transfer_call` (to initiate the transfer and enter the yield path) and `storage_deposit` (to fund the message account and trigger the resume). No special privileges, leaked keys, or off-chain coordination are needed beyond what the attacker already controls. [5](#0-4) 

---

### Recommendation

Re-apply the `NativeFeeRestricted` role check inside `init_transfer_resume`, mirroring the guard in `init_transfer`. If `storage_owner` holds the `NativeFeeRestricted` role and `transfer_message.fee.native_fee.0 > 0`, the resume should reject the transfer and return the full token amount as a refund, consistent with how other invalid-state resumes are handled.

---

### Proof of Concept

1. DAO grants `NativeFeeRestricted` role to attacker account via `acl_grant_role`.
2. Attacker calls `ft_transfer_call` on a token contract with `msg` containing `native_token_fee > 0`. Inside `ft_on_transfer` → `init_transfer`, the direct path is blocked by the role check; execution enters the yield path and a pending promise is registered.
3. Attacker calls `storage_deposit` for the message-storage account ID (deterministically derivable from the transfer parameters) with sufficient NEAR to cover storage + native fee.
4. The yield fires: `init_transfer_resume` is invoked. It calls `try_to_transfer_balance_from_message_account` (succeeds), then `init_transfer_internal` — **no role check is performed**.
5. The transfer is stored with the non-zero native fee. A relayer can now call `sign_transfer` and subsequently `claim_fee`, receiving the native fee — the `NativeFeeRestricted` restriction is fully bypassed. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1829-1836)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));
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
