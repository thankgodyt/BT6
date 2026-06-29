### Title
`NativeFeeRestricted` Role Bypass via Message Account Payment Path — (`near/omni-bridge/src/lib.rs`)

### Summary
The `NativeFeeRestricted` role is intended to prevent designated accounts from setting a non-zero `native_token_fee` in bridge transfers. However, the restriction check is only evaluated in one branch of a short-circuit `||` expression inside `init_transfer`, and is entirely absent from the `init_transfer_resume` callback. A `NativeFeeRestricted` account can bypass the restriction by pre-funding a message account, causing the first branch to succeed and the role check to be skipped.

### Finding Description
In `near/omni-bridge/src/lib.rs`, the `init_transfer` function decides whether to proceed immediately or yield execution using the following condition:

```rust
if self
    .try_to_transfer_balance_from_message_account(
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()                                          // ← branch A
    || (self.has_storage_balance(...)
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
                                                      // ← branch B (contains the check)
``` [1](#0-0) 

Due to short-circuit evaluation, if branch A (`try_to_transfer_balance_from_message_account` returns `Ok`) succeeds, branch B — which contains the only `NativeFeeRestricted` check — is never evaluated. A `NativeFeeRestricted` account can pre-fund the message account (whose address is deterministically derived from the transfer parameters) with enough balance to cover both storage and native fees, causing branch A to succeed and the role restriction to be silently skipped.

The second bypass path is the `init_transfer_resume` callback, which is invoked when the transfer is yielded. This function contains **no `NativeFeeRestricted` check at all**:

```rust
pub fn init_transfer_resume(...) -> U128 {
    self.remove_promise(&message_storage_account_id);
    // ...
    if let Err(err) = self.try_to_transfer_balance_from_message_account(...) {
        return transfer_message.amount;
    }
    self.init_transfer_internal(transfer_message, storage_owner)  // proceeds unconditionally
}
``` [2](#0-1) 

A `NativeFeeRestricted` account can trigger the yield path (by not pre-funding the message account initially), then fund the message account, and when `init_transfer_resume` fires it will proceed with `native_token_fee > 0` without any role check.

The `NativeFeeRestricted` role is defined alongside other access-control roles and is explicitly tested to block native fee usage: [3](#0-2) 

### Impact Explanation
The `NativeFeeRestricted` role is a bridge-level access control mechanism. Its bypass allows a restricted account to set arbitrary `native_token_fee` values in outbound bridge transfers, directly undermining the role's enforcement. This is a role bypass that lets a restricted actor execute bridge actions (fee-bearing transfers) that the protocol explicitly prohibits for that account class.

### Likelihood Explanation
The bypass is straightforward and requires no privileged access. The message account address is deterministically derivable from the transfer parameters. A `NativeFeeRestricted` account can compute it off-chain, fund it in one transaction, and then call `ft_transfer_call` with `native_token_fee > 0`. The restriction is completely ineffective against any account that is aware of this code path.

### Recommendation
Apply the `NativeFeeRestricted` check unconditionally before entering either execution path. Specifically:

1. Move the role check to the top of `init_transfer`, before the branch-A / branch-B split, so it gates the entire function regardless of how storage is paid.
2. Add the same check at the start of `init_transfer_resume`, since the transfer message already carries the `native_fee` value and the signer identity is available as `storage_owner`.

### Proof of Concept
1. Admin grants `NativeFeeRestricted` to account `alice.near`.
2. `alice.near` computes the deterministic `message_storage_account_id` for a transfer with `native_token_fee = 1 NEAR`.
3. `alice.near` calls `storage_deposit` on the bridge contract for that message account, depositing enough to cover storage + 1 NEAR native fee.
4. `alice.near` calls `ft_transfer_call` on the token contract targeting the bridge, with `msg` containing `native_token_fee = 1 NEAR`.
5. Inside `init_transfer`, `try_to_transfer_balance_from_message_account` succeeds (branch A is true).
6. The `||` short-circuits; the `acl_has_role(NativeFeeRestricted)` check on line 580 is never reached.
7. `init_transfer_internal` is called and the transfer is registered with `native_fee = 1 NEAR`, which will be paid to the relayer upon `sign_transfer`. [4](#0-3)

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
