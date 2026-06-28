### Title
Missing Pause Check in `finish_withdraw_v2` Allows Token Burns Without Transfer Completion - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `finish_withdraw_v2` function in the NEAR omni-bridge contract lacks a `#[pause]` attribute. When the bridge is paused (e.g., during a security incident), old bridge token contracts can still call this function, causing user tokens to be burned while the corresponding cross-chain transfer cannot be completed because `sign_transfer` is simultaneously paused.

---

### Finding Description

All primary transfer-initiating entry points in the NEAR omni-bridge contract are guarded by the `#[pause]` macro from `near_plugins`:

- `ft_on_transfer` — `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`
- `sign_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `fin_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `claim_fee` — `#[pause(except(roles(Role::DAO)))]`
- `deploy_token` — `#[pause(except(roles(Role::DAO)))]`
- `bind_token` — `#[pause(except(roles(Role::DAO)))]`

However, `finish_withdraw_v2` carries **no pause guard at all**: [1](#0-0) 

```rust
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
    let token_id = env::predecessor_account_id();
    require!(self.is_deployed_token(&token_id),);
    ...
    env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
}
```

This function is the legacy withdrawal entry point called by deployed bridge token contracts (old bridge token factory pattern). The calling token contract burns the user's tokens first, then calls `finish_withdraw_v2` to register the pending transfer. Because `finish_withdraw_v2` has no pause check, it succeeds and emits an `InitTransferEvent` even when the bridge is fully paused.

The downstream `sign_transfer` function, which relayers must call to produce the MPC signature needed to release funds on the destination chain, **is** paused: [2](#0-1) 

This creates an irreconcilable state: tokens are burned on NEAR, a pending transfer record exists, but no relayer can advance the transfer to completion.

Contrast with `ft_on_transfer`, which is the guarded path for new-style transfers: [3](#0-2) 

---

### Impact Explanation

When the bridge is paused (e.g., due to a discovered vulnerability), a user who interacts with a deployed legacy bridge token contract triggers the following sequence:

1. User calls the token contract (e.g., `ft_transfer_call` with a withdrawal message).
2. Token contract burns the user's tokens.
3. Token contract calls `finish_withdraw_v2` on the bridge — **succeeds** because there is no pause check.
4. Bridge records a pending `TransferMessage` and emits `InitTransferEvent`.
5. Relayer attempts `sign_transfer` — **reverts** because it is paused.
6. User's tokens are permanently burned on NEAR; the destination chain never receives funds.

If the bridge is paused indefinitely (e.g., due to a critical exploit requiring a contract upgrade), or if a contract migration does not preserve and honour the orphaned pending transfers, the user's funds are permanently lost. This matches the "permanent freezing of bridged funds" impact class.

---

### Likelihood Explanation

The bridge's pause mechanism is explicitly designed for emergency use. Legacy bridge token contracts that call `finish_withdraw_v2` remain deployed and active on mainnet (the bridge supports migrated tokens via `migrated_tokens`). A user unaware of the pause — or interacting through a UI that does not surface the paused state — can trigger this path. The attacker-controlled entry is the user's own call to the token contract; no privileged access is required.

---

### Recommendation

Add a `#[pause]` attribute to `finish_withdraw_v2`, consistent with all other transfer-initiating functions:

```rust
#[pause]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
```

Because `finish_withdraw_v2` is called by a token contract (not directly by a user), the token contract's call will revert when the bridge is paused, preventing the token burn from occurring in the first place and preserving user funds.

---

### Proof of Concept

1. Admin calls `pause` (or `PauseManager` triggers an emergency pause) on the NEAR omni-bridge, setting the paused flag.
2. User holds tokens in a legacy deployed bridge token contract (one that calls `finish_withdraw_v2` on withdrawal).
3. User calls `ft_transfer_call` on the token contract with a withdrawal message.
4. Token contract burns `amount` tokens from the user.
5. Token contract calls `omni-bridge.finish_withdraw_v2(sender_id, amount, recipient)`.
6. `finish_withdraw_v2` executes without checking pause state, increments `current_origin_nonce`, stores a `TransferMessage`, and emits `InitTransferEvent`.
7. Relayer calls `sign_transfer` → panics with pause error.
8. User's tokens are gone; no MPC signature is ever produced; destination chain never releases funds. [1](#0-0) [4](#0-3) [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L445-452)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
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
