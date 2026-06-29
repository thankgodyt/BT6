Audit Report

## Title
Pause Bypass via Async `fin_transfer_callback` Allows Token Minting/Unlocking When Contract Is Paused — (`near/omni-bridge/src/lib.rs`)

## Summary

The NEAR omni-bridge contract enforces a pause guard on `fin_transfer` via `#[pause(except(roles(Role::DAO)))]`, but the asynchronous callback `fin_transfer_callback` carries only `#[private]` with no pause check. Because NEAR promise callbacks execute in a later receipt — potentially in a different block — the contract can be paused between the two steps, and the callback will still complete the transfer, minting or unlocking tokens to the recipient in violation of the intended pause protection.

## Finding Description

`fin_transfer` at line 672 is decorated with `#[pause(except(roles(Role::DAO)))]`, preventing non-DAO callers from initiating new inbound finalizations while the contract is paused. It schedules a cross-contract proof-verification call and chains `fin_transfer_callback` as the continuation via `main_promise.then(...)` at line 687.

`fin_transfer_callback` at line 698 is marked only `#[private]` and `#[payable]` — it has no pause check. Inside the callback, `process_fin_transfer_to_near` is called for NEAR-bound transfers (line 735), which calls `send_tokens` to mint or transfer tokens to the recipient. For transfers routed to other chains, `process_fin_transfer_to_other_chain` is called (line 743), which records a new outbound transfer message and adjusts locked token accounting. Both are security-sensitive state changes that the pause mechanism is intended to block.

The same structural pattern exists in `deploy_token_callback` (called from the paused `deploy_token` at line 1136) and `bind_token_callback` (called from the paused `bind_token` at line 1223), but `fin_transfer_callback` is the highest-impact instance because it directly controls token issuance.

The `trusted_relayer` role required to call `fin_transfer` is permissionless: any external user can call `apply_for_trusted_relayer` with a stake deposit and, after the waiting period elapses, becomes a trusted relayer automatically. This is confirmed by the staking tests showing the auto-promotion flow. The rules explicitly list "relayer flows" as a valid trigger path.

## Impact Explanation

This is a **Critical** unauthorized pause bypass. A trusted relayer whose `fin_transfer` call was submitted before the pause will have their `fin_transfer_callback` execute regardless of the pause state. This causes the bridge to mint or release bridged tokens to the recipient even during a security incident for which the pause was activated. The impact directly matches the allowed scope: "Unauthorized authorization bypass, role bypass, pause bypass... that lets an attacker execute bridge... actions" and "Stealing, loss, double-spending, unauthorized minting... of bridged funds."

## Likelihood Explanation

NEAR promise callbacks execute in a subsequent receipt, which may land in a different block from the originating call. A `PauseManager` pausing the contract in response to a detected exploit cannot retroactively cancel already-scheduled callbacks. Any `fin_transfer` call submitted before the pause transaction is confirmed will produce a callback that bypasses the pause. This is a realistic race condition requiring no special attacker capability beyond being a registered trusted relayer (a permissionless, stake-based role) and submitting a normal bridge finalization.

## Recommendation

Add a pause guard at the start of `fin_transfer_callback`. Using the `near-plugins` `Pausable` trait already imported by the contract, check `self.is_paused()` (or apply the `#[pause]` macro) before processing the prover result. If the contract is paused, the callback should refund any attached deposit and return without minting or recording any state change. Apply the same fix to `deploy_token_callback` and `bind_token_callback`.

## Proof of Concept

1. A trusted relayer (any user who has staked NEAR and waited through the activation period) submits `fin_transfer` for a large inbound transfer (e.g., 1,000,000 USDC from Ethereum to NEAR). The call passes the pause check at line 672 and schedules `verify_proof` → `fin_transfer_callback`.
2. In the same or next block, a `PauseManager` detects an exploit and calls `pa_pause` to halt the contract.
3. In the following block, the NEAR runtime delivers the `fin_transfer_callback` receipt. Because `fin_transfer_callback` has no pause check (line 698–746), it reads the prover result, validates the factory, and calls `process_fin_transfer_to_near`, which calls `send_tokens` to mint 1,000,000 USDC to the recipient.
4. The pause intended to freeze all bridge operations has been bypassed; tokens have been minted during the incident window.

To reproduce: deploy the contract on a local sandbox, register a trusted relayer, submit `fin_transfer`, pause the contract in the next block before the callback receipt is processed, and observe that `fin_transfer_callback` still executes and tokens are minted.