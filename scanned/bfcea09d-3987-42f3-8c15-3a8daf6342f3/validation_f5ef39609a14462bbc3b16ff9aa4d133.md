### Title
`NativeFeeRestricted` Role Bypass via Pre-funded Message Storage Account — (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `NativeFeeRestricted` role restriction in `init_transfer()` is only enforced in one branch of a two-branch `||` condition. The first branch — `try_to_transfer_balance_from_message_account` — carries no role check at all. A restricted account can pre-fund the virtual message storage account via `storage_deposit`, causing the first branch to succeed and the role check to be skipped entirely.

### Finding Description
In `near/omni-bridge/src/lib.rs`, `init_transfer()` decides whether to proceed immediately or yield based on the following condition:

```rust
if self
    .try_to_transfer_balance_from_message_account(
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()                                                   // ← branch A: NO role check
|| (self.has_storage_balance(
        &signer_id,
        required_storage_balance.saturating_add(NearToken::from_yoctonear(
            init_transfer_msg.native_token_fee.0,
        )),
    ) && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
                                                               // ← branch B: role check here
``` [1](#0-0) 

The `NativeFeeRestricted` guard lives exclusively in branch B. If branch A evaluates to `true`, the entire `||` short-circuits and `init_transfer_internal` is called with the non-zero `native_token_fee` intact — no role check is ever performed. [2](#0-1) 

The `message_storage_account_id` is a deterministic virtual account derived from the transfer message:

```rust
let message_storage_account_id = transfer_message
    .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));
``` [3](#0-2) 

Because `storage_deposit` is a public function that accepts any `account_id`, any caller — including the `NativeFeeRestricted` account itself — can pre-fund this virtual account before initiating the transfer.

### Impact Explanation
A `NativeFeeRestricted` account can bypass the native-fee restriction and attach an arbitrary `native_token_fee` to a bridge transfer. This is a direct role bypass: the protocol explicitly marks certain accounts as forbidden from setting native fees (the role name and the test suite confirm this intent), yet the restriction is rendered ineffective. The bypassing account can use the native fee to prioritize relayer processing of its own transfers — a bridge action the role was designed to prohibit.

### Likelihood Explanation
The bypass requires only two standard, publicly available calls:

1. Compute the deterministic `message_storage_account_id` for the intended transfer (derivable off-chain from public inputs).
2. Call `storage_deposit` to fund that account with enough balance to cover `native_token_fee + required_storage_balance`.
3. Call `ft_transfer_call` with a non-zero `native_token_fee`.

No privileged access, leaked keys, or external dependencies are required. Any `NativeFeeRestricted` account can execute this sequence independently.

### Recommendation
Apply the `NativeFeeRestricted` guard to **both** branches. The simplest fix is to hoist the role check outside the storage-path selection:

```rust
let native_fee_allowed = init_transfer_msg.native_token_fee.0 == 0
    || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone());

require!(native_fee_allowed, BridgeError::OperationNotAllowed.as_ref());

if self
    .try_to_transfer_balance_from_message_account(...)
    .is_ok()
    || self.has_storage_balance(&signer_id, ...)
{
    ...
}
```

This ensures the role check is unconditional and cannot be bypassed by any storage-funding strategy.

### Proof of Concept
1. Alice holds `NativeFeeRestricted` role on the NEAR omni-bridge contract.
2. Alice constructs the `InitTransferMsg` she intends to submit (with `native_token_fee > 0`).
3. Alice derives `message_storage_account_id` from the resulting `TransferMessage` (deterministic, public inputs).
4. Alice calls `storage_deposit` on the bridge contract, crediting `message_storage_account_id` with `native_token_fee + required_storage_balance` yoctoNEAR.
5. Alice calls `ft_transfer_call` on the token contract, routing to the bridge with the crafted `InitTransferMsg`.
6. Inside `ft_on_transfer` → `init_transfer`, branch A (`try_to_transfer_balance_from_message_account`) succeeds because the message account is funded.
7. The `||` short-circuits; branch B (containing the `NativeFeeRestricted` check) is never evaluated.
8. `init_transfer_internal` is called with the non-zero `native_token_fee`, and the `InitTransferEvent` is emitted with the fee intact — bypassing the role restriction. [4](#0-3) [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L253-263)
```rust
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
```

**File:** near/omni-bridge/src/lib.rs (L562-563)
```rust
        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));
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
