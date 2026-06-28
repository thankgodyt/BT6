### Title
Pause Bypass via Missing `#[pause]` Guard on `finish_withdraw_v2` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

Every public bridge entry point that initiates or finalises a transfer is decorated with `#[pause]` (or `#[pause(except(...))]`). The single exception is `finish_withdraw_v2`, which is callable by any registered deployed-token contract and carries no pause guard. When the bridge is paused in response to an emergency, any holder of a legacy deployed token can still burn their tokens and inject a new pending `TransferMessage` into bridge state, partially bypassing the pause.

---

### Finding Description

All other state-mutating bridge entry points consistently apply the `near-plugins` `#[pause]` macro:

- `ft_on_transfer` → `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`
- `sign_transfer` → `#[pause(except(roles(Role::DAO)))]`
- `fin_transfer` → `#[pause(except(roles(Role::DAO)))]`
- `claim_fee` → `#[pause(except(roles(Role::DAO)))]`
- `deploy_token` → `#[pause(except(roles(Role::DAO)))]`
- `bind_token` → `#[pause(except(roles(Role::DAO)))]`
- `update_transfer_fee` → `#[pause]`

`finish_withdraw_v2` is the only public, state-mutating bridge function that carries **no** `#[pause]` attribute: [1](#0-0) 

Its sole guard is:

```rust
let token_id = env::predecessor_account_id();
require!(self.is_deployed_token(&token_id),);
``` [2](#0-1) 

Any account in `deployed_tokens` or `deployed_tokens_v2` satisfies this check. [3](#0-2) 

The function then unconditionally increments `current_origin_nonce`, allocates a `destination_nonce`, writes a new `TransferMessage` into `pending_transfers`, and emits an `InitTransferEvent` — all while the bridge is paused. [4](#0-3) 

---

### Impact Explanation

The bridge pause is the primary emergency-stop mechanism. When a pause is triggered (e.g., due to a discovered exploit in MPC signing or token accounting), operators expect **all** transfer-initiation paths to halt. Because `finish_withdraw_v2` bypasses the pause:

1. A token holder calls `withdraw` on any legacy deployed-token contract (e.g., an eNear-style token). The token contract burns the caller's tokens and cross-contract-calls `finish_withdraw_v2` on the bridge.
2. `finish_withdraw_v2` succeeds even while the bridge is paused, writing a new `TransferMessage` into `pending_transfers` and incrementing both `current_origin_nonce` and the per-chain `destination_nonces`.
3. The nonce state is permanently advanced. When the pause is lifted, the accumulated pending transfers are eligible for signing via `sign_transfer` and subsequent relay to Ethereum — potentially during a window when the underlying vulnerability has not yet been fully remediated.

This constitutes a **pause bypass** — an explicitly listed critical impact class — because it allows an unprivileged bridge user to execute a bridge action (transfer initiation, nonce advancement, state mutation) that the pause mechanism is designed to prevent.

---

### Likelihood Explanation

Any holder of a legacy deployed token (e.g., eNear) can trigger this path permissionlessly. No special role, no admin access, and no leaked key is required. The attacker-controlled entry is the standard `withdraw` call on the deployed token contract, which is a normal user-facing operation. Likelihood is **medium**: the window requires the bridge to be paused, but pauses are precisely the moments when this bypass is most harmful.

---

### Recommendation

Add `#[pause(except(roles(Role::DAO)))]` to `finish_withdraw_v2`, consistent with every other state-mutating bridge entry point:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn finish_withdraw_v2(
    &mut self,
    ...
```

This ensures the pause mechanism is enforced uniformly at the lowest level across all transfer-initiation paths, including the legacy withdrawal route.

---

### Proof of Concept

1. Bridge operator calls `pause()` on the bridge contract due to an emergency.
2. Attacker holds 100 units of a legacy deployed token (e.g., `eth-<addr>.factory.bridge.near`).
3. Attacker calls `withdraw(100, "0xAttackerEthAddress")` on the deployed token contract.
4. The token contract burns 100 tokens and calls `finish_withdraw_v2` on the bridge with `sender_id = attacker`, `amount = 100`, `recipient = "0xAttackerEthAddress"`.
5. `finish_withdraw_v2` executes without reverting: `current_origin_nonce` is incremented, a `TransferMessage` is inserted into `pending_transfers`, and `InitTransferEvent` is emitted — all while the bridge is paused.
6. When the pause is lifted, a relayer calls `sign_transfer` for the pending transfer, MPC signs it, and the attacker receives funds on Ethereum — potentially before the emergency that triggered the pause has been fully resolved.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1356-1358)
```rust
    pub fn is_deployed_token(&self, token: &AccountId) -> bool {
        self.deployed_tokens.contains(token) || self.deployed_tokens_v2.contains_key(token)
    }
```
