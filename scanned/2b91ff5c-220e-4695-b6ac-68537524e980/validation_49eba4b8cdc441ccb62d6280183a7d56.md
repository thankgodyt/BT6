### Title
Pause Bypass via `finish_withdraw_v2` Allows Outbound Transfer Initiation When Bridge Is Paused - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR `omni-bridge` contract pauses the primary outbound transfer entry point (`ft_on_transfer`) but leaves the legacy `finish_withdraw_v2` callback unguarded. Any user holding a deployed bridge token can call the token's withdraw function, which invokes `finish_withdraw_v2` on the bridge, creating a pending `InitTransfer` message and burning the user's tokens — even when the bridge is fully paused.

### Finding Description

The NEAR bridge uses the `near-plugins` `#[pause]` macro to halt bridge activity during emergencies. The primary inbound path for outbound transfers is `ft_on_transfer`, which is correctly gated: [1](#0-0) 

However, `finish_withdraw_v2` — a public function that creates a `TransferMessage` and emits an `InitTransferEvent` — carries **no pause check**: [2](#0-1) 

The function accepts a call from any `predecessor_account_id` that passes `self.is_deployed_token()`, burns the caller-supplied `amount` (already deducted by the token contract), increments `current_origin_nonce`, and writes a `TransferMessage` to `pending_transfers`: [3](#0-2) 

The downstream `sign_transfer` is paused, so the transfer cannot be signed while the bridge is paused. However, the transfer message is durably stored and the user's tokens are already burned. When the bridge is unpaused, any relayer can immediately call `sign_transfer` on all accumulated pending transfers, completing them without any further user action.

### Impact Explanation

**Impact: High.** When operators pause the bridge in response to a security incident (e.g., suspected MPC key compromise, abnormal on-chain activity), the intent is to halt all new cross-chain transfer initiations. `finish_withdraw_v2` defeats this intent: users can burn bridge tokens and queue outbound transfers that will be automatically processed the moment the bridge is unpaused. If the pause was triggered because of a vulnerability in the signing or finalization path, these queued transfers will be processed through the same vulnerable path once unpaused, potentially resulting in loss of bridged funds.

### Likelihood Explanation

**Likelihood: Low.** The bridge must be in a paused state, and the attacker must hold deployed bridge tokens and know to use the legacy `finish_withdraw_v2` path rather than the standard `ft_on_transfer` path. The window is limited to the pause duration.

### Recommendation

Add the `#[pause]` attribute (or an equivalent `#[pause(except(roles(Role::DAO)))]`) to `finish_withdraw_v2`, consistent with how `ft_on_transfer` and `sign_transfer` are protected:

```rust
#[pause]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
```

### Proof of Concept

1. Admin calls `pause` on the NEAR bridge (e.g., via `PauseManager` role), setting the global pause flag.
2. `ft_on_transfer` now reverts for any non-DAO caller — the standard outbound path is blocked.
3. Attacker holds `N` units of a deployed bridge token (e.g., `wETH.bridge.near`).
4. Attacker calls the bridge token's `withdraw` (or equivalent) function, which burns `N` tokens and cross-contract-calls `finish_withdraw_v2` on the bridge with `sender_id = attacker`, `amount = N`, `recipient = <EVM address>`.
5. `finish_withdraw_v2` has no pause check — it succeeds, increments `current_origin_nonce`, writes a `TransferMessage` to `pending_transfers`, and emits `InitTransferEvent`.
6. The attacker's tokens are now burned and a pending transfer exists.
7. When the bridge is unpaused, any relayer calls `sign_transfer` on the pending transfer, the MPC signs it, and the relayer finalizes it on the EVM side — completing the cross-chain transfer that was initiated during the pause window. [1](#0-0) [4](#0-3) [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L1314-1355)
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
