### Title
`NativeFeeRestricted` Role Bypass via Pre-funded Message Account in `init_transfer` — (File: near/omni-bridge/src/lib.rs)

### Summary
The `NativeFeeRestricted` role check inside `init_transfer` is placed only in the second branch of a short-circuit OR condition. When the first branch — `try_to_transfer_balance_from_message_account` — succeeds, the role check is never evaluated. An account that has been assigned the `NativeFeeRestricted` role can pre-fund the deterministic message-storage account and thereby bypass the restriction entirely, submitting a transfer with a non-zero `native_token_fee`.

### Finding Description
In `init_transfer`, the gate that decides whether to proceed immediately or yield execution is:

```rust
if self
    .try_to_transfer_balance_from_message_account(
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()                                                   // ← Branch 1 (no role check)
    || (self.has_storage_balance(
        &signer_id,
        required_storage_balance.saturating_add(NearToken::from_yoctonear(
            init_transfer_msg.native_token_fee.0,
        )),
    ) && (init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
                                                               // ← Branch 2 (role check here)
``` [1](#0-0) 

The `NativeFeeRestricted` role guard (`!self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())`) is evaluated **only** when Branch 1 returns `Err`. If Branch 1 returns `Ok`, Rust's short-circuit evaluation skips Branch 2 entirely, including the role check.

`message_storage_account_id` is derived deterministically from the transfer message and the caller-supplied `external_id`:

```rust
let message_storage_account_id = transfer_message
    .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));
``` [2](#0-1) 

Because `external_id` is attacker-controlled, the attacker can compute the exact account ID that will be used, pre-deposit funds into it, and make Branch 1 succeed on demand.

### Impact Explanation
The `NativeFeeRestricted` role is an explicit access-control mechanism intended to prevent designated accounts from attaching a native NEAR fee to outbound transfers. Bypassing it is a role/authorization bypass: the restricted account can embed an arbitrary `native_token_fee` in the emitted `InitTransferEvent`, which relayers observe and use to claim a native-token payment. The restriction is rendered completely ineffective for any account willing to pre-fund the message-storage account.

### Likelihood Explanation
The attacker must already hold the `NativeFeeRestricted` role (i.e., an admin has previously restricted them). However, once restricted, the bypass requires only two permissionless on-chain actions: (1) compute the deterministic `message_storage_account_id` for a chosen `external_id`, and (2) call `storage_deposit` on the bridge to fund that account. No privileged access, leaked keys, or off-chain coordination is needed beyond what the attacker already controls.

### Recommendation
Hoist the `NativeFeeRestricted` role check outside the OR condition so it is evaluated unconditionally whenever `native_token_fee > 0`, regardless of which payment branch succeeds:

```rust
// Guard applied before the storage-payment branching
if init_transfer_msg.native_token_fee.0 > 0 {
    require!(
        !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
        BridgeError::NativeFeeRestricted.as_ref()
    );
}

if self.try_to_transfer_balance_from_message_account(...).is_ok()
    || (self.has_storage_balance(...) && init_transfer_msg.native_token_fee.0 == 0)
    || self.has_storage_balance(...)
{
    ...
}
```

This ensures the role restriction cannot be circumvented by any storage-payment path.

### Proof of Concept
1. Admin grants `NativeFeeRestricted` to `attacker.near`.
2. `attacker.near` picks any `external_id` (e.g., `"bypass-1"`) and computes the resulting `message_storage_account_id` off-chain using the same logic as `calculate_storage_account_id`.
3. `attacker.near` calls `storage_deposit` on the bridge contract, crediting the computed account ID with `required_storage_balance + native_token_fee` yoctoNEAR.
4. `attacker.near` calls `ft_transfer_call` on a registered token, routing to the bridge with an `InitTransferMsg` containing `native_token_fee = 1_000_000_000_000_000_000_000_000` (1 NEAR) and `external_id = "bypass-1"`.
5. Inside `init_transfer`, `try_to_transfer_balance_from_message_account` finds the pre-funded account and returns `Ok`.
6. The OR short-circuits; the `NativeFeeRestricted` role check in Branch 2 is never reached.
7. `init_transfer_internal` is called and an `InitTransferEvent` is emitted with the non-zero `native_fee`, which relayers will honour when claiming fees — bypassing the intended restriction entirely. [3](#0-2)

### Citations

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
