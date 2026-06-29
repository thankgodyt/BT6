### Title
`NativeFeeRestricted` Role Bypass via Pre-Funded Message Storage Account — (`File: near/omni-bridge/src/lib.rs`)

### Summary
The `init_transfer` function in the NEAR omni-bridge contract enforces the `NativeFeeRestricted` role only inside one branch of a two-branch `||` condition. An account that holds the `NativeFeeRestricted` role can bypass the restriction entirely by pre-funding the deterministic message storage account, causing the first branch to succeed and the role check to be skipped.

### Finding Description
In `near/omni-bridge/src/lib.rs`, the `init_transfer` function decides whether to proceed immediately or yield execution via the following compound condition:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // Branch A — NO role check
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(...)                 // Branch B — role check present
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
{
    // transfer proceeds
``` [1](#0-0) 

Branch B correctly enforces the `NativeFeeRestricted` role: if `native_token_fee > 0` and the signer holds `NativeFeeRestricted`, the condition is `false` and the transfer does not proceed immediately. However, Branch A — `try_to_transfer_balance_from_message_account(...).is_ok()` — contains **no role check at all**. If Branch A evaluates to `true`, the entire `||` short-circuits and Branch B (including the role check) is never evaluated.

The `message_storage_account_id` is computed deterministically from the transfer message fields:

```rust
let message_storage_account_id = transfer_message
    .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));
``` [2](#0-1) 

Because the storage account ID is deterministic and publicly computable, any account can pre-fund it before calling `ft_transfer_call`.

### Impact Explanation
A `NativeFeeRestricted` account can set a non-zero `native_token_fee` on any outbound transfer, completely bypassing the access control restriction that was explicitly designed to prevent this. The `NativeFeeRestricted` role is rendered ineffective. This is a role bypass: an account explicitly restricted from a protocol action can perform that action by exploiting the missing check in Branch A.

### Likelihood Explanation
The exploit requires only that the attacker:
1. Holds the `NativeFeeRestricted` role (i.e., is a normal bridge user who has been restricted).
2. Computes the deterministic `message_storage_account_id` for their intended transfer.
3. Pre-funds that account via `storage_deposit` before calling `ft_transfer_call`.

All three steps are permissionless and require no privileged access beyond being a normal NEAR account. The `NativeFeeRestricted` role is granted by the DAO to specific accounts, so the attacker population is exactly the set of accounts the protocol intended to restrict.

### Recommendation
Add the `NativeFeeRestricted` role check to Branch A as well, so that a pre-funded message account cannot be used to bypass the restriction:

```rust
if self
    .try_to_transfer_balance_from_message_account(...)
    .is_ok()
    && (init_transfer_msg.native_token_fee.0 == 0          // <-- add this guard
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()))
    || (self.has_storage_balance(...)
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
```

Alternatively, hoist the `NativeFeeRestricted` check to the very top of `init_transfer`, before any branching, so it cannot be bypassed by any storage path.

### Proof of Concept
1. DAO grants `NativeFeeRestricted` to `attacker.near`.
2. `attacker.near` constructs a `TransferMessage` with `native_token_fee = 1_000_000_000_000_000_000_000_000` (1 NEAR).
3. `attacker.near` calls `calculate_storage_account_id` (or replicates the deterministic derivation off-chain) to obtain `message_storage_account_id`.
4. `attacker.near` calls `storage_deposit` on the bridge contract, crediting `message_storage_account_id` with sufficient balance.
5. `attacker.near` calls `ft_transfer_call` on the token contract with the same transfer parameters.
6. Inside `init_transfer`, `try_to_transfer_balance_from_message_account` succeeds (Branch A = `true`), the `||` short-circuits, and `init_transfer_internal` is called with `native_token_fee = 1 NEAR` — despite `attacker.near` holding `NativeFeeRestricted`. [3](#0-2)

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
