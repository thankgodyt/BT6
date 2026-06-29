Audit Report

## Title
Missing Pause Guard on `finish_withdraw_v2` Allows Transfer Initiation During Emergency Stop — (File: near/omni-bridge/src/lib.rs)

## Summary

`finish_withdraw_v2` is a public function callable by any account registered as a deployed token, but it carries no `#[pause]` attribute. Every other transfer-initiating entry point in the contract is protected by a pause guard. A holder of any legacy rainbow-bridge token (e.g., `*.factory.bridge.near`) can call `withdraw` on the token contract during a full bridge pause, causing the token contract to burn their NEAR-side tokens and cross-contract-call `finish_withdraw_v2`, which executes unconditionally, queuing the transfer and incrementing nonces.

## Finding Description

`finish_withdraw_v2` at lines 1314–1354 of `near/omni-bridge/src/lib.rs` is decorated only with `#[allow(clippy::needless_pass_by_value)]` — no `#[pause]` macro is present:

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
    ...
    self.add_transfer_message(transfer_message.clone(), sender_id.clone());
    env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
}
```

Compare with every other transfer-initiating public function:

| Function | Pause guard |
|---|---|
| `ft_on_transfer` (L252) | `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]` |
| `sign_transfer` (L446) | `#[pause(except(roles(Role::DAO)))]` |
| `fin_transfer` (L672) | `#[pause(except(roles(Role::DAO)))]` |
| `finish_withdraw_v2` (L1314) | **none** |

The only access control is `require!(self.is_deployed_token(&token_id))`, which passes for any account in `deployed_tokens` or `deployed_tokens_v2`. The `is_deployed_token` check at line 1356–1358 is satisfied by legacy rainbow-bridge token accounts. The `add_transfer_message` helper at lines 2180–2191 contains no pause check of its own — it only checks for key uniqueness.

The exploit path is a cross-contract callback: the legacy token's `withdraw` method burns the caller's tokens first, then calls `finish_withdraw_v2` on the bridge. Because the burn is irreversible and happens before the bridge callback, the user's NEAR-side tokens are destroyed regardless of the bridge's pause state.

## Impact Explanation

This is a concrete **pause bypass**: an unprivileged external user can initiate an outbound bridge transfer (NEAR → ETH) while the bridge is fully paused. The consequences are:

1. **Irreversible token burn** — the legacy token contract burns the user's tokens before the callback; there is no rollback path if the bridge is paused.
2. **Nonce corruption** — `current_origin_nonce` and `destination_nonces[Eth]` are incremented during the pause window, potentially creating gaps or ordering issues in the nonce sequence.
3. **Transfer queued in `pending_transfers`** — the `TransferMessage` is stored and will be eligible for `sign_transfer` (which is paused) the moment the bridge is unpaused, potentially before the security issue that triggered the pause is resolved.
4. **`InitTransferEvent` emitted** — relayers observe the event and may attempt processing.

This matches the allowed critical impact: *"pause bypass… that lets an attacker execute bridge… actions."*

## Likelihood Explanation

The bridge explicitly tracks legacy rainbow-bridge tokens via `deployed_tokens` and `deployed_tokens_v2`, and the `get_token_origin_chain` heuristic at lines 1427–1451 recognizes accounts matching `factory.bridge.near`, `eth.*`, etc. as first-class citizens. These tokens implement the old rainbow-bridge callback pattern where `withdraw` burns and then calls `finish_withdraw_v2`. No special role or permission is required — any token holder can trigger this path. The function is in production code with no deprecation guard.

## Recommendation

Add the same pause guard used by all other transfer-initiating functions:

```rust
#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
```

If `finish_withdraw_v2` is intended to be deprecated, replace the body with an unconditional `env::panic_str` so no legacy token can invoke it.

## Proof of Concept

1. Deploy the NEAR omni-bridge contract with a legacy `factory.bridge.near` token registered in `deployed_tokens`.
2. Call `pause_all()` on the bridge (sets all pause flags).
3. As a normal user holding legacy tokens, call `withdraw(amount, eth_recipient)` on the legacy token contract.
4. The token contract burns `amount` from the caller and cross-contract-calls `finish_withdraw_v2` on the bridge with `sender_id = caller`, `amount`, `recipient = eth_recipient`.
5. Observe that `finish_withdraw_v2` executes without reverting: `current_origin_nonce` is incremented, a `TransferMessage` is inserted into `pending_transfers`, and `InitTransferEvent` is emitted — all while the bridge is fully paused.
6. Confirm the user's NEAR tokens are permanently burned with no recourse.
7. Unpause the bridge; call `sign_transfer` for the queued transfer ID; observe that the MPC signs the payload and ETH-side tokens are released — completing a transfer that was initiated during the pause window. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1314-1322)
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
```

**File:** near/omni-bridge/src/lib.rs (L1356-1358)
```rust
    pub fn is_deployed_token(&self, token: &AccountId) -> bool {
        self.deployed_tokens.contains(token) || self.deployed_tokens_v2.contains_key(token)
    }
```

**File:** near/omni-bridge/src/lib.rs (L1427-1451)
```rust
        let origin_chain = match token.as_str() {
            s if s.starts_with("eth")
                || s.contains("factory.bridge.near")
                || s.contains("factory.sepolia.testnet") =>
            {
                ChainKind::Eth
            }
            s if s.starts_with("base") => ChainKind::Base,
            s if s.starts_with("arb") => ChainKind::Arb,
            s if s.starts_with("bnb") => ChainKind::Bnb,
            s if s.starts_with("pol") => ChainKind::Pol,
            s if s.starts_with("hlevm") => ChainKind::HyperEvm,
            s if s.starts_with("abs") => ChainKind::Abs,
            s if s.starts_with("sol") => ChainKind::Sol,
            s if s.starts_with("fogo") => ChainKind::Fogo,
            s if s.starts_with("strk") || s.starts_with("starknet") => ChainKind::Strk,
            _ => env::panic_str(&BridgeError::CannotDetermineOriginChain.as_ref()),
        };

        if !origin_chain.is_utxo_chain() {
            self.deployed_tokens_v2.insert(token, &origin_chain);
        }

        origin_chain
    }
```

**File:** near/omni-bridge/src/lib.rs (L2180-2191)
```rust
    fn add_transfer_message(
        &mut self,
        transfer_message: TransferMessage,
        message_owner: AccountId,
    ) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.insert_raw_transfer(transfer_message, message_owner,)
                .is_none(),
            BridgeError::KeyExists.as_ref()
        );
        env::storage_byte_cost().saturating_mul((env::storage_usage() - storage_usage).into())
```
