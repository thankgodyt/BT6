Audit Report

## Title
Missing Pause Guard in `finish_withdraw_v2` Enables Transfer Initiation During Emergency Pause - (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `finish_withdraw_v2` function in the NEAR omni-bridge contract lacks a `#[pause]` attribute, unlike every other transfer-initiating public function. Any user holding tokens in a registered legacy bridge token factory can trigger this path via a cross-contract call, causing nonce increments, persistent `TransferMessage` storage, and `InitTransferEvent` emission — all while the bridge is in an emergency-paused state.

## Finding Description
Every transfer-initiating public function in the contract carries a pause guard:
- `ft_on_transfer` — `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]` (L252)
- `sign_transfer` — `#[pause(except(roles(Role::DAO)))]` (L446)
- `fin_transfer` — `#[pause(except(roles(Role::DAO)))]` (L672)

`finish_withdraw_v2` (L1314–1354) has no such attribute. Its only access control is:

```rust
let token_id = env::predecessor_account_id();
require!(self.is_deployed_token(&token_id),);
```

Any account registered in `deployed_tokens` or `deployed_tokens_v2` satisfies this check. Legacy bridge token factory contracts are registered there and expose user-facing `withdraw` functions that cross-contract-call `finish_withdraw_v2`. When called, the function unconditionally:
1. Increments `current_origin_nonce` and `destination_nonces` for `ChainKind::Eth`
2. Persists a `TransferMessage` via `add_transfer_message`
3. Charges storage to `env::current_account_id()`
4. Emits `OmniBridgeEvent::InitTransferEvent`

All four state-mutating steps execute with no pause check.

## Impact Explanation
This is a concrete pause bypass — an impact class explicitly listed as Critical. The pause mechanism's purpose is to halt all bridge operations during an emergency. `finish_withdraw_v2` allows an unprivileged external user to execute a bridge action (transfer initiation: nonce increment, message persistence, event emission) while the bridge is paused. Queued `InitTransferEvent`s are observed by relayers; once the bridge is unpaused, relayers call `sign_transfer` to complete the transfers. If the bridge was paused to contain an active exploit in the transfer path, pre-queued transfers can be processed the moment the bridge resumes, before operators have time to clear the pending queue. Additionally, each call charges storage to the bridge's own account, enabling a storage drain attack against the protocol.

## Likelihood Explanation
The preconditions are realistic and require no special privilege: legacy bridge token factory contracts are already registered in `deployed_tokens`; any ordinary token holder can call `withdraw` on such a factory, which cross-contract-calls `finish_withdraw_v2`. The bridge's pause state is publicly observable on-chain, so an attacker can time calls precisely to the pause window. The path is repeatable for every token unit held.

## Recommendation
Add `#[pause(except(roles(Role::DAO)))]` to `finish_withdraw_v2`, consistent with all other transfer-initiating functions:

```rust
#[pause(except(roles(Role::DAO)))]
#[allow(clippy::needless_pass_by_value)]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) { ... }
```

## Proof of Concept
1. Deploy a local NEAR testnet with the omni-bridge contract and a legacy bridge token factory registered in `deployed_tokens`.
2. Call `pa_pause_feature` (or equivalent) to pause the bridge.
3. As an ordinary user, call `withdraw(amount, eth_recipient)` on the token factory.
4. Observe that the factory cross-contract-calls `finish_withdraw_v2` on the bridge.
5. Confirm via contract state inspection that `current_origin_nonce` incremented, a `TransferMessage` was stored in `pending_transfers`, and `InitTransferEvent` was logged — all while the bridge is paused.
6. Confirm that `sign_transfer` called directly during the pause is rejected by its pause guard, demonstrating the asymmetry.
7. Unpause the bridge; observe the relayer picks up the queued event and calls `sign_transfer` to complete the transfer. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L1344-1353)
```rust
        let required_storage_balance =
            self.add_transfer_message(transfer_message.clone(), sender_id.clone());

        self.update_storage_balance(
            env::current_account_id(),
            required_storage_balance,
            NearToken::from_yoctonear(0),
        );

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
```
