Audit Report

## Title
Pause Bypass via Unguarded `fin_transfer_callback` Allows Token Minting/Unlocking When Contract Is Paused — (`near/omni-bridge/src/lib.rs`)

## Summary

`fin_transfer` is protected by `#[pause(except(roles(Role::DAO)))]`, preventing new inbound transfer finalizations while the contract is paused. However, the asynchronous continuation `fin_transfer_callback` carries only `#[private]` and no pause check. Because NEAR promise callbacks execute in a subsequent receipt — potentially in a different block — a pause activated between the two steps does not prevent the callback from minting or unlocking tokens. The same pattern exists in `deploy_token_callback` and `bind_token_callback`, but `fin_transfer_callback` is the highest-impact instance.

## Finding Description

`fin_transfer` is gated by the pause macro and the `#[trusted_relayer]` guard:

```rust
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise { ... }
```

It schedules `verify_proof` and chains `fin_transfer_callback` as the continuation. `fin_transfer_callback` is marked only `#[private]`:

```rust
#[private]
#[payable]
pub fn fin_transfer_callback(
    &mut self,
    #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
    #[serializer(borsh)] predecessor_account_id: AccountId,
) -> PromiseOrValue<Nonce> { ... }
```

Inside the callback, for NEAR-bound transfers `process_fin_transfer_to_near` is called (which mints or transfers tokens to the recipient), and for other-chain transfers `process_fin_transfer_to_other_chain` is called (which records a new outbound transfer message and unlocks tokens). Neither path checks the pause state. Once `fin_transfer` passes its pause check and schedules the callback, the NEAR runtime will deliver the callback receipt regardless of any subsequent pause.

The same structural gap exists in `deploy_token_callback` (no pause check, deploys a new token contract) and `bind_token_callback` (no pause check, registers token bindings and initializes locked-token accounting).

## Impact Explanation

This is a concrete **pause bypass** enabling **unauthorized minting or unlocking of bridged funds** during a security incident. When the contract is paused in response to an exploit, any `fin_transfer` call already in flight will have its callback execute, minting or releasing tokens to the recipient. This directly matches the allowed Critical impact class: "Unauthorized transaction, authorization bypass, role bypass, pause bypass… that lets an attacker execute bridge… actions" and "Stealing, loss, double-spending, unauthorized minting… of bridged funds."

## Likelihood Explanation

Triggering this requires only that a trusted relayer submits `fin_transfer` before the pause transaction is confirmed — a normal, routine bridge operation. "Relayer flows" are explicitly listed as a valid trigger path. No malicious intent is required from the relayer; the race condition arises from NEAR's asynchronous execution model. A `PauseManager` cannot retroactively cancel already-scheduled promise receipts. Any `fin_transfer` submitted in the same or a preceding block to the pause will produce a callback that bypasses the pause. This is repeatable for every in-flight finalization at the time of a pause event.

## Recommendation

Add a pause guard at the start of `fin_transfer_callback`. Using the `Pausable` trait already imported by the contract, check `self.is_paused()` (or apply the `#[pause]` macro) before processing the prover result. If the contract is paused, the callback should refund any attached deposit and return without minting or recording any state change. Apply the same fix to `deploy_token_callback` and `bind_token_callback`.

## Proof of Concept

1. The bridge is operating normally. A trusted relayer submits `fin_transfer` for a large inbound transfer (e.g., 1,000,000 USDC from Ethereum to NEAR). The call passes the `#[pause]` and `#[trusted_relayer]` checks and schedules `verify_proof` → `fin_transfer_callback`.
2. In the same or next block, a `PauseManager` detects an exploit and calls `pa_pause` to halt the contract.
3. In the following block, the NEAR runtime delivers the `fin_transfer_callback` receipt. Because `fin_transfer_callback` has no pause check, it reads the prover result, validates the factory, and calls `process_fin_transfer_to_near`, which mints 1,000,000 USDC to the recipient.
4. The pause intended to freeze all bridge operations has been bypassed; tokens have been minted during the incident window.

To reproduce locally: write a unit test that (a) calls `fin_transfer_callback` directly (bypassing `fin_transfer`) with a valid `ProverResult::InitTransfer` in the promise results, (b) sets the contract's pause state to paused before the callback call, and (c) asserts that the callback still completes the mint/unlock. The existing test `test_fin_transfer_callback_near_fails_without_locked_tokens` demonstrates that `fin_transfer_callback` can be called directly in unit tests, confirming the absence of any pause guard.