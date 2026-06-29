Audit Report

## Title
Missing Pause Guard on `finish_withdraw_v2` Allows Transfer Initiation While Bridge Is Paused - (File: near/omni-bridge/src/lib.rs)

## Summary

`finish_withdraw_v2` is a public entry point callable by any deployed bridge token contract that creates a pending outbound `TransferMessage`, increments the origin nonce, and emits an `InitTransferEvent` — all without any `#[pause]` guard. Every other transfer-initiating and transfer-finalizing function in the contract carries a pause attribute, making this an inconsistent and exploitable gap. A user holding a deployed bridge token can queue an outbound transfer while the bridge is fully paused, with their NEAR-side tokens already burned at call time.

## Finding Description

The contract applies `#[pause]` uniformly to all critical public entry points:

- `ft_on_transfer` — `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]` [1](#0-0) 
- `sign_transfer` — `#[pause(except(roles(Role::DAO)))]` [2](#0-1) 
- `fin_transfer` — `#[pause(except(roles(Role::DAO)))]` [3](#0-2) 

`finish_withdraw_v2`, however, carries no pause attribute whatsoever: [4](#0-3) 

The only guard present is `require!(self.is_deployed_token(&token_id))`, which verifies the caller is a registered bridge token — a condition any user can satisfy by holding tokens in a deployed bridge token contract. [5](#0-4) 

When called, the function:
1. Increments `current_origin_nonce` and `destination_nonces`
2. Inserts a `TransferMessage` into `pending_transfers`
3. Emits `OmniBridgeEvent::InitTransferEvent` [6](#0-5) 

All three steps are identical to the `init_transfer` path that is correctly blocked by the pause on `ft_on_transfer`. The token burn on the NEAR-side token contract occurs *before* `finish_withdraw_v2` is called, meaning the user's NEAR-side balance is already destroyed at the point where a pause check would have intervened.

## Impact Explanation

This is a concrete pause bypass matching the allowed critical impact: *"Unauthorized transaction, authorization bypass, role bypass, pause bypass... that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."*

When the bridge is paused to contain a live exploit, the `ft_on_transfer` → `init_transfer` path is correctly blocked. However, any holder of a deployed bridge token can still burn their NEAR-side tokens and queue a `TransferMessage` in `pending_transfers`. Upon unpausing, relayers call `sign_transfer` (which is then unblocked) and the queued transfers are finalized on Ethereum — fully bypassing the pause window. Additionally, if the bridge is paused indefinitely, the user's already-burned NEAR tokens are permanently frozen with no recourse, constituting permanent freezing of bridged funds.

## Likelihood Explanation

No special role or privilege is required. Any user holding tokens in a deployed bridge token contract (e.g., legacy rainbow bridge tokens registered in `deployed_tokens` or `deployed_tokens_v2`) can trigger this path by calling `withdraw` on the token contract. The token contract performs the burn and cross-contract-calls `finish_withdraw_v2` on the bridge. This is a standard, documented user-facing flow. The bridge has deployed tokens on mainnet (`omni.bridge.near`), making this immediately exploitable by any token holder.

## Recommendation

Add the same pause guard used on `ft_on_transfer` to `finish_withdraw_v2`:

```rust
#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
```

This ensures that when the bridge is paused, the legacy withdrawal callback path is blocked at the bridge level, consistent with all other transfer-initiation paths. [7](#0-6) 

## Proof of Concept

1. Admin calls `pa_pause_feature` to fully pause the bridge.
2. User holds tokens in a deployed bridge token contract (e.g., `eth-token.bridge.near`) registered in `deployed_tokens` or `deployed_tokens_v2`.
3. User calls `withdraw(amount, eth_recipient)` on the token contract.
4. Token contract burns the user's NEAR-side balance and cross-contract-calls `finish_withdraw_v2` on `omni.bridge.near`.
5. `finish_withdraw_v2` executes with no pause check: `current_origin_nonce` is incremented, a `TransferMessage` is inserted into `pending_transfers`, and `InitTransferEvent` is emitted. [6](#0-5) 
6. When the bridge is later unpaused, a relayer calls `sign_transfer` for the queued transfer ID.
7. The MPC signer signs the payload; the user receives tokens on Ethereum — having fully bypassed the pause window.

**Local test plan**: Deploy the bridge contract on a NEAR sandbox, register a mock token contract in `deployed_tokens`, pause the bridge via `pa_pause_feature`, call `finish_withdraw_v2` directly from the mock token account, and assert that `pending_transfers` contains the new entry and `InitTransferEvent` was logged — confirming the pause had no effect.

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

**File:** near/omni-bridge/src/lib.rs (L1314-1320)
```rust
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish_withdraw_v2(
        &mut self,
        #[serializer(borsh)] sender_id: &AccountId,
        #[serializer(borsh)] amount: u128,
        #[serializer(borsh)] recipient: String,
    ) {
```

**File:** near/omni-bridge/src/lib.rs (L1321-1322)
```rust
        let token_id = env::predecessor_account_id();
        require!(self.is_deployed_token(&token_id),);
```

**File:** near/omni-bridge/src/lib.rs (L1324-1353)
```rust
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
```
