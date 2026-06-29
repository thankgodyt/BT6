### Title
`NativeFeeRestricted` Role Can Be Bypassed via Token Transfer to a Clean Account - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `NativeFeeRestricted` role is intended to prevent certain accounts from setting a non-zero `native_token_fee` when initiating bridge transfers. However, the restriction is checked against `signer_id` (`env::signer_account_id()`), not `sender_id`. A restricted account can trivially bypass this by transferring their tokens to any other account they control and initiating the transfer from that clean account.

### Finding Description
In `ft_on_transfer`, the contract explicitly separates `sender_id` (the account that called `ft_transfer_call` on the token contract) from `signer_id` (the actual transaction signer), noting that `sender_id` can be spoofed: [1](#0-0) 

The `NativeFeeRestricted` role check inside `init_transfer` is performed exclusively against `signer_id`: [2](#0-1) 

Because the check is on `signer_id` and not on `sender_id` (the actual token holder initiating the bridge transfer), a `NativeFeeRestricted` account can:

1. Transfer their tokens to any fresh, unrestricted account they control (`clean.near`).
2. Have `clean.near` call `ft_transfer_call` on the token contract with a non-zero `native_token_fee` in the message.
3. Since `clean.near` does not hold the `NativeFeeRestricted` role, the check at line 580 passes.
4. The transfer is accepted with a non-zero native fee, and the restriction is fully bypassed.

The `sender` field in the resulting `TransferMessage` is set to `sender_id` (the clean account), not the restricted account: [3](#0-2) 

### Impact Explanation
An account assigned `NativeFeeRestricted` can fully circumvent the role's intended restriction by routing tokens through any secondary account it controls. This constitutes a role bypass: the restricted account can set arbitrary non-zero native fees, incentivizing relayers with NEAR tokens in ways the protocol explicitly intended to prevent for that account. The bypass is permanent as long as the account can create or control additional NEAR accounts (which is always possible and cheap on NEAR).

### Likelihood Explanation
Exploitation requires only that the restricted account hold tokens and be able to create or control a second NEAR account — both trivially achievable by any NEAR user. No privileged access, leaked keys, or external dependencies are required. The bypass is a single `ft_transfer` followed by a `ft_transfer_call` from the clean account.

### Recommendation
The `NativeFeeRestricted` check should be applied to `sender_id` (the actual token holder initiating the transfer) in addition to, or instead of, `signer_id`. Since the contract already acknowledges that `sender_id` can be spoofed for storage payment purposes, the role check should be applied to both identities, or the protocol should document and accept that `NativeFeeRestricted` is trivially bypassable by design (as was done for `SOFT_RESTRICTED_STAKER_ROLE` in the referenced report).

### Proof of Concept
1. Admin grants `NativeFeeRestricted` to `restricted.near`.
2. `restricted.near` calls `ft_transfer` on the token contract to send tokens to `clean.near` (a fresh account it controls).
3. `clean.near` calls `ft_transfer_call` on the token contract with `receiver_id = locker_contract` and `msg` containing `native_token_fee > 0`.
4. `ft_on_transfer` is invoked: `sender_id = clean.near`, `signer_id = clean.near`.
5. The check `!self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())` evaluates to `true` because `clean.near` has no role.
6. `init_transfer_internal` is called and the transfer is stored with a non-zero `native_fee`, bypassing the restriction entirely. [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** near/omni-bridge/src/lib.rs (L252-263)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
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

**File:** near/omni-bridge/src/lib.rs (L540-553)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
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
