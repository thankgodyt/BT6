### Title
Pause Bypass via `finish_withdraw_v2` Allows Outbound Transfer Initiation When Bridge Is Paused — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR `omni-bridge` contract exposes a secondary transfer-initiation path, `finish_withdraw_v2`, that is callable by any deployed bridge token contract. Unlike the primary path (`ft_on_transfer`), this function carries no `#[pause]` guard. When governance pauses the bridge, users can still initiate outbound NEAR → EVM transfers by interacting with a deployed bridge token that calls back into `finish_withdraw_v2`, bypassing the intended pause.

---

### Finding Description

The primary outbound transfer entry point is `ft_on_transfer`, which is decorated with the `#[pause]` macro:

```rust
#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
``` [1](#0-0) 

When the bridge is paused, this blocks all `InitTransfer`, `FastFinTransfer`, and `UtxoFinTransfer` messages routed through `ft_on_transfer`.

However, a second public transfer-initiation path exists — `finish_withdraw_v2` — which has **no pause check at all**:

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

    let transfer_message = TransferMessage { ... };
    ...
    env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
}
``` [2](#0-1) 

This function:
- Is publicly callable by any account that `is_deployed_token` returns `true` for (i.e., any bridge token deployed through the bridge).
- Increments `current_origin_nonce`, writes a `TransferMessage` to `pending_transfers`, and emits `InitTransferEvent` — the exact same state mutations and event that `ft_on_transfer → init_transfer` produces.
- Has **no** `#[pause]` attribute, unlike every other state-mutating transfer function in the contract.

The access gate (`require!(self.is_deployed_token(&token_id))`) only checks that the caller is a registered bridge token, not that the bridge is unpaused. A user can call the bridge token's own `withdraw` (or equivalent burn-and-callback) function, which cross-contract-calls `finish_withdraw_v2` on the bridge, completing an outbound transfer initiation regardless of the bridge's pause state.

---

### Impact Explanation

An outbound transfer initiated through `finish_withdraw_v2` while the bridge is paused will be stored in `pending_transfers` and will emit `InitTransferEvent`. A relayer can then call `sign_transfer` (which itself has `#[pause(except(roles(Role::DAO)))]`) — but note that `sign_transfer` is only blocked for non-DAO callers. If governance pauses the bridge specifically to halt all outbound transfers (e.g., due to a discovered vulnerability in the signing or finalization path), the `finish_withdraw_v2` bypass means pending transfers can still be queued and, once the bridge is unpaused, signed and finalized. This undermines the governance pause as a complete emergency stop for outbound transfers.

The impact class matches the external report: **a function of the protocol is available in moments it should not be**, allowing users to perform bridge actions that governance intended to block.

---

### Likelihood Explanation

Any holder of a deployed bridge token (e.g., a wrapped ERC-20 bridged from Ethereum) can trigger this path. The bridge token's withdraw/burn callback is a standard, documented user-facing operation. No special role or privilege is required beyond holding bridge tokens. The path is reachable on mainnet at `omni.bridge.near` with any token registered via `deployed_tokens` or `deployed_tokens_v2`. [3](#0-2) 

---

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
``` [4](#0-3) 

---

### Proof of Concept

1. Governance calls `pause` on the NEAR `omni-bridge` contract, setting the bridge to a paused state.
2. Confirm that a direct `ft_transfer_call` to the bridge with an `InitTransfer` message panics with the pause error.
3. User calls `withdraw(amount, eth_recipient)` (or equivalent burn-and-callback) on a deployed bridge token (e.g., `eth-usdc.omni.bridge.near`).
4. The bridge token burns the user's tokens and cross-contract-calls `finish_withdraw_v2` on `omni.bridge.near` with `sender_id`, `amount`, and `recipient`.
5. `finish_withdraw_v2` executes without reverting: `current_origin_nonce` is incremented, a `TransferMessage` is inserted into `pending_transfers`, and `InitTransferEvent` is emitted.
6. The outbound transfer is now queued despite the bridge being paused — the pause has been bypassed. [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
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
