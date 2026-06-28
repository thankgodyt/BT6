### Title
`NativeFeeRestricted` Role Bypass via Yield Path in `init_transfer_resume` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function enforces the `NativeFeeRestricted` role to block certain accounts from setting a non-zero `native_token_fee`. When the direct execution path cannot be taken (insufficient storage balance), the function creates a NEAR yield that resumes via `init_transfer_resume`. That resume callback does **not** re-check the `NativeFeeRestricted` role, allowing a restricted account to complete a transfer with a non-zero native fee by simply funding the message-storage account.

---

### Finding Description

In `init_transfer`, the guard that enforces the restriction is embedded inside the branch condition that selects between the direct path and the yield path:

```rust
if self.try_to_transfer_balance_from_message_account(...).is_ok()
|| (self.has_storage_balance(&signer_id, ...)
    && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
{
    // direct path → init_transfer_internal
} else {
    // yield path → promise_yield_create("init_transfer_resume", ...)
}
```

When a `NativeFeeRestricted` account submits a transfer with `native_token_fee > 0`, the condition evaluates to `false` and execution falls into the **yield path**. The transfer message (already containing the non-zero `native_fee`) is serialised and stored as yield arguments. [1](#0-0) 

The resume callback `init_transfer_resume` is `#[private]` and fires when someone deposits to the derived message-storage account. It contains **no** `NativeFeeRestricted` check:

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
    ) { ... }

    self.init_transfer_internal(transfer_message, storage_owner)  // ← no role check
}
``` [2](#0-1) 

The message-storage account ID is deterministically derived from the transfer parameters and is publicly known. Any caller — including the restricted account itself — can call `storage_deposit` on that account to trigger the resume. [3](#0-2) 

---

### Impact Explanation

A `NativeFeeRestricted` account can bypass the role restriction and submit `init_transfer` messages with an arbitrary non-zero `native_token_fee`. This is a **role bypass**: the DAO-assigned access-control restriction is rendered ineffective for any account that deliberately triggers the yield path. The native fee is minted or transferred to the relayer upon `claim_fee`, meaning the bypass has a concrete on-chain effect (native token disbursement to a relayer of the attacker's choice). [4](#0-3) 

---

### Likelihood Explanation

The `NativeFeeRestricted` role is assigned by the DAO to accounts the protocol wants to restrict. Any such account can trivially trigger the yield path (the signer simply needs to not have a pre-funded storage balance, or can arrange for the message account to not exist yet) and then self-fund the message-storage account to resume execution. No special privileges beyond holding the restricted role are required.

---

### Recommendation

Add the `NativeFeeRestricted` check inside `init_transfer_resume` before calling `init_transfer_internal`:

```rust
if transfer_message.fee.native_fee.0 != 0
    && self.acl_has_role(Role::NativeFeeRestricted.into(), storage_owner.clone())
{
    env::log_str("NativeFeeRestricted: native fee not allowed");
    return transfer_message.amount;
}
self.init_transfer_internal(transfer_message, storage_owner)
```

This mirrors the guard already present in the direct path of `init_transfer`. [5](#0-4) 

---

### Proof of Concept

1. DAO grants `NativeFeeRestricted` to `attacker.near`.
2. `attacker.near` calls `ft_transfer_call` on a registered token with `msg` containing `native_token_fee = 1_000_000_000_000_000_000_000_000` (1 NEAR) and does **not** pre-fund their bridge storage balance.
3. `init_transfer` evaluates the branch condition: `try_to_transfer_balance_from_message_account` fails (no message account), and `NativeFeeRestricted && native_fee != 0` makes the second clause false → **yield path taken**. The transfer message with `native_fee = 1 NEAR` is stored as yield arguments.
4. `attacker.near` calls `storage_deposit` on the bridge contract with `account_id = <derived message account>` and deposits enough NEAR to cover storage + native fee.
5. The yield fires; `init_transfer_resume` runs, calls `try_to_transfer_balance_from_message_account` (succeeds), then calls `init_transfer_internal` — **no role check performed**.
6. The transfer is registered with `native_fee = 1 NEAR`. A relayer calls `sign_transfer` and then `claim_fee`; `send_fee_internal` mints/transfers 1 NEAR to the relayer. [6](#0-5) [7](#0-6)

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
