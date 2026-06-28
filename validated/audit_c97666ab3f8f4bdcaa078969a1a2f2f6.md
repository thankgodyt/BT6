### Title
Pause Bypass via `finish_withdraw_v2` Allows Token Burns With No Corresponding Payout - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR `omni-bridge` contract implements a `Pausable` mechanism that gates all user-facing transfer entry points behind a `#[pause]` attribute. However, the legacy withdrawal function `finish_withdraw_v2` is missing this guard. When the bridge is paused, a user can still trigger this function through a deployed token contract's `withdraw` call, causing their tokens to be burned on NEAR while the resulting pending transfer can never be completed — permanently destroying user funds.

### Finding Description

The `omni-bridge` contract uses `near-plugins`' `Pausable` trait and applies `#[pause(except(roles(Role::DAO)))]` or `#[pause]` to every public transfer entry point:

- `ft_on_transfer` — `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`
- `sign_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `fin_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `claim_fee` — `#[pause(except(roles(Role::DAO)))]`
- `deploy_token` — `#[pause(except(roles(Role::DAO)))]`
- `bind_token` — `#[pause(except(roles(Role::DAO)))]`
- `log_metadata` — `#[pause(except(roles(Role::DAO)))]`

The legacy function `finish_withdraw_v2`, however, carries **no pause attribute**: [1](#0-0) 

```rust
#[allow(clippy::needless_pass_by_value)]
pub fn finish_withdraw_v2(
    &mut self,
    sender_id: &AccountId,
    amount: u128,
    recipient: String,
) {
    let token_id = env::predecessor_account_id();
    require!(self.is_deployed_token(&token_id),);
    ...
    env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
}
```

Its only access control is that `env::predecessor_account_id()` must be a deployed bridge token. [2](#0-1) 

A deployed token contract's `withdraw` function calls `finish_withdraw_v2` on the bridge after burning the caller's tokens. Because the token contract is a separate, independent contract, its `withdraw` path is not subject to the bridge's pause state. The bridge's pause only blocks `ft_on_transfer` (the modern path), leaving the legacy path fully open.

The function increments `current_origin_nonce`, allocates a `TransferMessage` in `pending_transfers`, and emits an `InitTransferEvent` — all while the bridge is paused. [3](#0-2) 

### Impact Explanation

Once `finish_withdraw_v2` records the pending transfer, the only way to complete it is via `sign_transfer`, which **is** paused for non-DAO callers: [4](#0-3) 

The user's NEAR-side tokens are already burned by the token contract before `finish_withdraw_v2` is called. With `sign_transfer` blocked, the MPC signature that would release funds on the destination EVM chain can never be produced. The pending transfer sits in storage indefinitely. The user loses their tokens with no recourse — a **permanent, irrecoverable loss of bridged funds**.

### Likelihood Explanation

The bridge pause is an emergency mechanism intended to halt all transfers during an incident (e.g., a discovered exploit, a migration). Users who are unaware of the pause, or who deliberately try to race the pause, can call `withdraw` on any deployed bridge token at any time. The deployed token contracts are independent contracts with no knowledge of the bridge's pause state. This path is reachable by any unprivileged token holder with zero special access.

### Recommendation

Add `#[pause(except(roles(Role::DAO)))]` to `finish_withdraw_v2`, consistent with every other transfer-initiating function in the contract:

```rust
#[allow(clippy::needless_pass_by_value)]
#[pause(except(roles(Role::DAO)))]
pub fn finish_withdraw_v2(
    &mut self,
    ...
```

Additionally, audit all other public functions callable by external contracts (not just by end users directly) to ensure the pause invariant is uniformly enforced across every transfer entry path.

### Proof of Concept

1. Admin pauses the bridge (e.g., due to a discovered vulnerability), intending to halt all transfers.
2. Alice holds 1000 `eth.bridge.near` tokens (a deployed bridge token).
3. Alice calls `withdraw("0xAliceEthAddress", 1000)` on the `eth.bridge.near` token contract.
4. The token contract burns Alice's 1000 tokens and calls `finish_withdraw_v2` on the bridge.
5. `finish_withdraw_v2` has no pause check — it succeeds, recording a pending `TransferMessage` with `origin_nonce = N` and emitting `InitTransferEvent`.
6. A relayer attempts to call `sign_transfer` to produce the MPC signature for Alice's transfer — this call **reverts** because `sign_transfer` is paused.
7. Alice's 1000 tokens are permanently burned. No EVM-side release ever occurs. Funds are lost. [5](#0-4) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L1445-1447)
```rust

        if !origin_chain.is_utxo_chain() {
            self.deployed_tokens_v2.insert(token, &origin_chain);
```
