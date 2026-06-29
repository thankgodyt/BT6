The code matches all citations in the report. Let me verify the `send_tokens` function more fully and check for any existing guards.

Audit Report

## Title
Silent `ft_transfer` Failure Not Detected in `fin_transfer_send_tokens_callback` Permanently Locks Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

## Summary

When `process_fin_transfer_to_near` dispatches a plain `ft_transfer` (non-`ft_transfer_call` path), the callback `fin_transfer_send_tokens_callback` delegates the refund decision to `is_refund_required(false)`, which unconditionally returns `false` without inspecting the promise result. If `ft_transfer` fails for any reason — token contract paused, recipient blacklisted, or any panic — the bridge still emits `FinTransferEvent` and the transfer ID remains permanently in `finalised_transfers`, with no recovery path for the user's funds.

## Finding Description

`process_fin_transfer_to_near` calls `add_fin_transfer` at L1875, which inserts the transfer ID into `finalised_transfers` (replay protection). It then calls `send_tokens`, which at L2102–2106 dispatches a plain `ft_transfer` when the token is not a deployed bridge token and `msg` is empty. The callback is registered at L1967–1977 with `is_ft_transfer_call = !msg.is_empty()`, which evaluates to `false` for this path.

Inside `fin_transfer_send_tokens_callback` (L1702), `is_refund_required(false)` is called. The implementation at L1800–1802 unconditionally returns `false` for the non-`ft_transfer_call` case without reading `env::promise_result(0)` at all. Consequently, even when the `ft_transfer` receipt fails, the callback falls into the `else` branch (L1719–1746): it emits `FinTransferEvent` and never calls `remove_fin_transfer`. The transfer ID stays in `finalised_transfers` permanently. Any retry attempt panics with `BridgeError::TransferAlreadyFinalised`. The tokens remain in the bridge contract because the failed `ft_transfer` receipt reverts on the token contract side, but the bridge's state was committed in a prior receipt.

The `ft_transfer_call` path, by contrast, correctly reads the promise result inside `is_refund_required(true)` at L1785–1799 and triggers the refund branch when the call fails.

## Impact Explanation

This is a direct instance of the Critical impact class: **permanent freezing of bridged funds**. When `ft_transfer` fails:
1. The transfer ID is irrevocably recorded in `finalised_transfers` — replay protection blocks any retry.
2. The tokens remain locked in the bridge contract with no withdrawal or recovery mechanism.
3. `FinTransferEvent` is emitted, so the NEAR-side indexer and MPC network consider the transfer complete.
4. The user's funds are permanently frozen with no on-chain recourse.

## Likelihood Explanation

Several NEP-141 tokens supported by the bridge (e.g., USDC.e, USDT) implement pause and blacklist functionality that is exercised in practice. No attacker action is required: a legitimate cross-chain transfer initiated by any user is sufficient. If the token contract is paused or the recipient is blacklisted at the moment the `ft_transfer` receipt executes — a window that can span multiple NEAR blocks — the failure is silently swallowed. The condition is realistic, repeatable, and requires no privileged access.

## Recommendation

In `fin_transfer_send_tokens_callback`, check the promise result unconditionally regardless of `is_ft_transfer_call`. Extend `is_refund_required` (or replace it) so that when `is_ft_transfer_call` is `false`, it calls `env::promise_result_checked(0, ...)` and returns `true` on a `Failed` result. When the refund branch is triggered for the `ft_transfer` path, call `remove_fin_transfer`, revert lock actions, burn deployed tokens if needed, and emit `FailedFinTransferEvent` instead of `FinTransferEvent` — mirroring the existing refund logic already present in the `ft_transfer_call` path.

## Proof of Concept

1. User initiates a transfer of a pausable NEP-141 token (e.g., USDC.e) from Ethereum to NEAR with an empty `msg` field.
2. The EVM `initTransfer` locks tokens and emits `InitTransfer`.
3. A relayer calls `fin_transfer` on the NEAR bridge with a valid proof.
4. `fin_transfer_callback` → `process_fin_transfer_to_near` → `add_fin_transfer` (L1875) inserts the transfer ID into `finalised_transfers`.
5. `send_tokens` dispatches `ft_transfer` (L2102–2106) because `msg.is_empty()` is `true` and the token is not a deployed bridge token.
6. The token contract is paused (or the recipient is blacklisted) at the time the `ft_transfer` receipt executes. The receipt fails.
7. `fin_transfer_send_tokens_callback` runs with `is_ft_transfer_call = false`.
8. `is_refund_required(false)` returns `false` at L1800–1802 — the failed promise result is never read.
9. The callback emits `FinTransferEvent` (L1745) and returns without calling `remove_fin_transfer`.
10. Any subsequent retry panics with `BridgeError::TransferAlreadyFinalised` (L2228–2230).
11. The user's tokens are permanently locked in the bridge contract.