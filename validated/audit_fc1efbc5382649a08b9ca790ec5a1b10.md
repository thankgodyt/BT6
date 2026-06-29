Looking at the actual code to verify the claim's key assertions.

Audit Report

## Title
Unregistered Native Token Causes Permanent `fin_transfer_callback` Revert for Transfers with `native_fee > 0` — (File: near/omni-bridge/src/lib.rs)

## Summary

When a cross-chain transfer arrives at NEAR with `native_fee > 0`, `process_fin_transfer_to_near` calls `get_native_token_id` to resolve the origin chain's native token. If `deploy_native_token` has not been called for that chain, `get_native_token_id` panics with `TokenNotRegistered`, reverting the entire `fin_transfer_callback` execution — including the preceding `add_fin_transfer` call. Because the transfer ID is never committed to `finalised_transfers`, every resubmission of the proof fails identically, leaving the user's funds permanently locked or burned on the source chain with no on-chain recovery path until DAO intervention.

## Finding Description

**Root cause — `get_native_token_id` panics unconditionally on missing registration:**

`get_native_token_id` (lines 1407–1412) constructs the zero-address for the given chain and delegates to `get_token_id` (lines 1368–1376), which calls `.near_expect(BridgeError::TokenNotRegistered)` — a hard panic — when the address is absent from `token_address_to_id`. There is no `Option`-returning variant and no guard at the call site.

**Critical ordering in `process_fin_transfer_to_near`:**

```
line 1875: self.add_fin_transfer(...)          // marks transfer as finalised
...
line 1936: self.get_native_token_id(...)        // panics if native token unregistered
```

`add_fin_transfer` (line 1875) mutates `finalised_transfers` before `get_native_token_id` is called (line 1936). A panic at line 1936 causes NEAR's runtime to roll back all state changes in the current execution context, including the `finalised_transfers` insertion. The transfer ID is therefore never persisted, so the proof can be resubmitted — but every resubmission hits the same panic.

**Second call site — `fin_transfer_send_tokens_callback` (line 1736–1742):** This callback executes after `add_fin_transfer` has already been committed in a prior execution context, so a panic here does not un-finalize the transfer; it only silently drops the native fee mint. This is a separate, lower-severity issue.

**Third call site — `send_fee_internal` / `claim_fee_callback` (line 2669):** Same pattern; panics here after the transfer message has been removed.

**Existing checks are insufficient:** The `fin_transfer` entry point (line 673) validates the relayer role and proof, but performs no check on whether the origin chain's native token is registered before dispatching to `fin_transfer_callback`. The EVM `initTransfer` cannot enforce this cross-chain invariant.

## Impact Explanation

This matches the allowed Critical impact: **permanent freezing of bridged funds**. The user's tokens are locked or burned on the source chain at the moment `initTransfer` executes. On NEAR, `fin_transfer_callback` reverts on every attempt. The transfer ID never enters `finalised_transfers`, so the proof is perpetually replayable but perpetually failing. Funds remain frozen until the DAO calls `deploy_native_token` for the origin chain — an action that may be delayed or never performed for newly onboarded chains. No unprivileged on-chain action can unblock the transfer.

## Likelihood Explanation

The `native_fee` field is freely set by the user at the source chain level with no cross-chain validation. The scenario is most likely during the onboarding window of new chains (e.g., `HyperEvm`, `Abs`, `Fogo` — all present in `OmniAddress::new_zero` and `get_native_token_address`), where the chain may be added to the bridge before `deploy_native_token` is called. Any user who sets `native_fee > 0` during this window triggers the freeze. The condition is reachable by any unprivileged external user through the standard `initTransfer` → `fin_transfer` cross-chain flow.

## Recommendation

1. In `process_fin_transfer_to_near`, before calling `get_native_token_id`, check whether the native token is registered. If not, either reject the transfer with a clear error (so the relayer can handle it) or treat `native_fee` as zero and refund it to the sender.
2. Change `get_native_token_id` to return `Option<AccountId>` instead of panicking, and propagate the `None` case gracefully at all call sites.
3. Alternatively, enforce at the source chain contract level that `native_fee > 0` is only accepted when the native token is known to be deployed on NEAR (requires an oracle or admin-maintained flag).

## Proof of Concept

1. DAO adds `HyperEvm` to the bridge (`factories.insert`) but does **not** call `deploy_native_token(HyperEvm, ...)`, so `token_address_to_id` has no entry for `HyperEvm(H160::ZERO)`.
2. User calls `initTransfer` on the HyperEvm `OmniBridge` with `native_fee = 1000`, `amount = 100_000`. Tokens are locked in the EVM bridge.
3. Relayer submits the proof to NEAR via `fin_transfer(...)`.
4. `fin_transfer_callback` decodes the proof, constructs `transfer_message`, and calls `process_fin_transfer_to_near`.
5. Line 1875: `add_fin_transfer` inserts the transfer ID into `finalised_transfers` (state change pending).
6. Line 1936: `get_native_token_id(ChainKind::HyperEvm)` → `get_native_token_address(HyperEvm)` returns `OmniAddress::HyperEvm(H160::ZERO)` → `token_address_to_id.get(HyperEvm(H160::ZERO))` returns `None` → `.near_expect(TokenNotRegistered)` panics.
7. NEAR runtime rolls back all state changes in `fin_transfer_callback`, including the `finalised_transfers` insertion.
8. Every subsequent resubmission of the same proof fails identically at step 6.
9. User's tokens remain locked in the EVM bridge with no unprivileged recovery path.

To reproduce as a unit test: mirror the structure of `test_fin_transfer_callback_near_success` but omit the `token_address_to_id` insertion for the native zero address and set `native_fee > 0` in the prover result; assert that the call panics with `TokenNotRegistered` and that `finalised_transfers` does not contain the transfer ID afterward.