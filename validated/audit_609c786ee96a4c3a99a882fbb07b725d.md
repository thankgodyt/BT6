### Title
Missing Pause Check on `finish_withdraw_v2` Allows Transfer Initiation While Bridge Is Paused - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR `omni-bridge` contract uses the `near_plugins::Pausable` framework and applies `#[pause]` attributes to all externally reachable transfer-initiating functions. However, `finish_withdraw_v2` — a public function callable by any deployed bridge token — is missing this guard. When the bridge is paused, governance cannot prevent users from initiating outbound transfers through the legacy bridge-token withdrawal path.

### Finding Description

Every user-facing transfer entry point in the NEAR bridge contract carries a `#[pause]` attribute:

- `ft_on_transfer` → `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]` [1](#0-0) 
- `sign_transfer` → `#[pause(except(roles(Role::DAO)))]` [2](#0-1) 
- `fin_transfer` → `#[pause(except(roles(Role::DAO)))]` [3](#0-2) 
- `claim_fee` → `#[pause(except(roles(Role::DAO)))]` [4](#0-3) 
- `deploy_token` → `#[pause(except(roles(Role::DAO)))]` [5](#0-4) 

`finish_withdraw_v2`, however, carries **no** `#[pause]` attribute:

```rust
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
    let token_id = env::predecessor_account_id();
    require!(self.is_deployed_token(&token_id),);

    self.current_origin_nonce += 1;
    let destination_nonce = self.get_next_destination_nonce(ChainKind::Eth);
    // ... builds TransferMessage and emits InitTransferEvent
``` [6](#0-5) 

The function is callable by any account that passes `self.is_deployed_token`, i.e., any bridge token deployed through the bridge's own deployer. It increments `current_origin_nonce` and `destination_nonce`, stores a `TransferMessage` in `pending_transfers`, and emits an `InitTransferEvent` — the exact same state mutations that `ft_on_transfer → init_transfer` performs, but without the pause gate.

### Impact Explanation

When the `PauseManager` or `DAO` pauses the bridge (e.g., in response to a security incident), the intent is to halt all bridge activity. Because `finish_withdraw_v2` is unguarded:

1. A user holding legacy bridge tokens can call the token contract's withdrawal/burn function.
2. The token contract burns the user's NEP-141 tokens and calls `finish_withdraw_v2` on the bridge.
3. The bridge records a pending `TransferMessage` and emits `InitTransferEvent` — bypassing the pause.
4. `sign_transfer` is paused, so the MPC signature cannot be obtained while the pause is active. The user's tokens are burned on NEAR with no corresponding release on EVM until the bridge is unpaused.
5. If the bridge is paused permanently (e.g., due to a critical exploit requiring contract replacement), the user's tokens are permanently frozen with no recourse.

This is a **pause bypass**: governance cannot achieve a complete halt of bridge activity, and users who interact with the legacy withdrawal path during a pause suffer irreversible token loss.

### Likelihood Explanation

The `finish_withdraw_v2` function is a public, production entry point reachable by any holder of a deployed bridge token. The bridge has deployed tokens for multiple assets. Any user who holds such tokens and calls the token's withdrawal function during a pause will trigger this path. No special privileges are required beyond holding bridge tokens.

### Recommendation

Add `#[pause(except(roles(Role::DAO)))]` to `finish_withdraw_v2`, consistent with all other transfer-initiating functions:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
```

Additionally, ensure the calling bridge token contract handles a panic/revert from `finish_withdraw_v2` gracefully (i.e., rolls back the burn) so that a pause does not cause token loss on the token-contract side.

### Proof of Concept

1. Governance calls `pause` with all flags set; the bridge is fully paused.
2. Alice holds 1000 `bridged-usdc.bridge.near` tokens (a deployed bridge token).
3. Alice calls `withdraw(amount=1000, recipient="0xAlice")` on `bridged-usdc.bridge.near`.
4. The token contract burns Alice's 1000 tokens and calls `finish_withdraw_v2("alice.near", 1000, "0xAlice")` on the bridge.
5. `finish_withdraw_v2` has no pause check → executes successfully, stores a `TransferMessage`, emits `InitTransferEvent`.
6. Alice's tokens are burned on NEAR. No relayer can call `sign_transfer` (paused). Alice's funds are frozen.
7. If the bridge is never unpaused, Alice permanently loses 1000 USDC. [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L446-447)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L672-673)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L1056-1057)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L1137-1138)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn deploy_token(&mut self, #[serializer(borsh)] args: DeployTokenArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L1314-1354)
```rust
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish_withdraw_v2(
        &mut self,
        #[serializer(borsh)] sender_id: &AccountId,
        #[serializer(borsh)] amount: u128,
        #[serializer(borsh)] recipient: String,
    ) {
        let token_id = env::predecessor_account_id();
        require!(self.is_deployed_token(&token_id),);

        self.current_origin_nonce += 1;
        let destination_nonce = self.get_next_destination_nonce(ChainKind::Eth);

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount: U128(amount),
            recipient: OmniAddress::Eth(
                H160::from_str(&recipient).near_expect(BridgeError::InvalidRecipientAddress),
            ),
            fee: Fee {
                fee: U128(0),
                native_fee: U128(0),
            },
            sender: OmniAddress::Near(sender_id.clone()),
            msg: String::new(),
            destination_nonce,
            origin_transfer_id: None,
        };

        let required_storage_balance =
            self.add_transfer_message(transfer_message.clone(), sender_id.clone());

        self.update_storage_balance(
            env::current_account_id(),
            required_storage_balance,
            NearToken::from_yoctonear(0),
        );

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
    }
```
