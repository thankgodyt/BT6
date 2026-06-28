### Title
Pause Bypass via `finish_withdraw_v2` — Outbound Transfers Can Be Initiated While Bridge Is Paused - (File: near/omni-bridge/src/lib.rs)

---

### Summary

`finish_withdraw_v2` is a public entry point in the NEAR bridge contract that creates a pending outbound `TransferMessage` and emits an `InitTransferEvent`. Unlike every other transfer-initiation path, it carries **no pause guard**, allowing any holder of a deployed bridge token to queue an outbound transfer even when the bridge is fully paused.

---

### Finding Description

The NEAR bridge contract applies `#[pause]` (or `#[pause(except(roles(...)))]`) uniformly to all critical public entry points:

| Function | Pause guard |
|---|---|
| `ft_on_transfer` | `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]` |
| `sign_transfer` | `#[pause(except(roles(Role::DAO)))]` |
| `fin_transfer` | `#[pause(except(roles(Role::DAO)))]` |
| `claim_fee` | `#[pause(except(roles(Role::DAO)))]` |
| `deploy_token` | `#[pause(except(roles(Role::DAO)))]` |
| `bind_token` | `#[pause(except(roles(Role::DAO)))]` | [1](#0-0) [2](#0-1) [3](#0-2) 

`finish_withdraw_v2`, however, is a **public function with no pause attribute**:

```rust
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
    let token_id = env::predecessor_account_id();
    require!(self.is_deployed_token(&token_id),);
    // ... increments nonce, builds TransferMessage, calls add_transfer_message, emits InitTransferEvent
}
``` [4](#0-3) 

This function is the legacy withdrawal callback invoked by deployed bridge tokens (e.g., old rainbow bridge tokens). When a user calls `withdraw` on such a token, the token burns the user's NEAR-side balance and cross-contract-calls `finish_withdraw_v2` on the bridge. The bridge then:

1. Increments `current_origin_nonce` and `destination_nonces`
2. Inserts a `TransferMessage` into `pending_transfers`
3. Emits `OmniBridgeEvent::InitTransferEvent` [5](#0-4) 

Steps 1–3 are identical to the `init_transfer` path that is correctly blocked by the pause on `ft_on_transfer`. The emitted `InitTransferEvent` is what relayers monitor to trigger `sign_transfer`.

---

### Impact Explanation

When the bridge is paused to halt all transfer activity (e.g., in response to a security incident), the `ft_on_transfer` → `init_transfer` path is correctly blocked. However, any user holding a deployed bridge token can still:

1. Call `withdraw` on the token contract
2. The token burns their NEAR-side tokens and calls `finish_withdraw_v2` on the bridge
3. The bridge stores a pending `TransferMessage` and emits `InitTransferEvent` — **no pause check is performed**

The pending transfer sits in `pending_transfers`. Once the bridge is unpaused, relayers call `sign_transfer` and the transfer is finalized on Ethereum. If the bridge was paused specifically to contain a live exploit, these queued transfers can be processed after the pause is lifted, extending the exploit window. Furthermore, the user's tokens are **already burned** at call time — before any pause check would have intervened — leaving funds in limbo if the bridge is never unpaused.

This is a direct analog to the reported vulnerability: the deactivation/pause check is applied to the primary operation path (`ft_on_transfer`) but is absent from an economically equivalent secondary path (`finish_withdraw_v2`), allowing the restriction to be bypassed.

---

### Likelihood Explanation

The bridge has deployed tokens on mainnet (`omni.bridge.near`). Any token holder whose token contract implements a `withdraw`-style callback to `finish_withdraw_v2` can trigger this path without any special role or privilege. No admin compromise is required.

---

### Recommendation

Add the same pause guard used on `ft_on_transfer` to `finish_withdraw_v2`:

```rust
#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
``` [1](#0-0) 

---

### Proof of Concept

1. Admin pauses the bridge (e.g., `PauseManager` calls `pa_pause_feature`).
2. User holds tokens in a deployed bridge token contract (e.g., `eth-token.bridge.near`) that implements a `withdraw` function calling `finish_withdraw_v2` on the bridge.
3. User calls `withdraw(amount, eth_recipient)` on the token contract.
4. Token contract burns the user's balance and cross-contract-calls `finish_withdraw_v2` on `omni.bridge.near`.
5. Bridge executes `finish_withdraw_v2` — **no pause check fires** — stores a `TransferMessage` in `pending_transfers`, and emits `InitTransferEvent`.
6. When the bridge is later unpaused, a relayer calls `sign_transfer` for the queued transfer.
7. The MPC signer signs the payload; the user receives tokens on Ethereum — having fully bypassed the pause. [4](#0-3)

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
