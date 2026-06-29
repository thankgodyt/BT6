Audit Report

## Title
Silent `ft_transfer` Failure Permanently Freezes Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`fin_transfer_send_tokens_callback` delegates the refund/revert decision entirely to `is_refund_required`, which returns `false` unconditionally when `is_ft_transfer_call` is `false` — without ever inspecting the promise result of the preceding `send_tokens` call. When a plain `ft_transfer` to the recipient fails at the NEAR runtime level (e.g., USDC/USDT blacklist, paused token), the callback silently proceeds to pay the relayer fee and emit `FinTransferEvent`, leaving the transfer permanently finalized, `locked_tokens` accounting permanently decremented, and the user's tokens irrecoverable inside the bridge contract.

## Finding Description
`process_fin_transfer_to_near` (L1875) calls `add_fin_transfer` and `unlock_tokens_if_needed` before issuing `send_tokens`, so state is mutated before the promise resolves. `send_tokens` (L2102–2106) uses plain `ft_transfer` (not `ft_transfer_call`) when `msg` is empty and the token is neither wNEAR nor a deployed bridge token. The resulting promise is chained to `fin_transfer_send_tokens_callback` (L1967–1977).

Inside the callback, `is_refund_required(is_ft_transfer_call)` (L1702) is the sole branch condition. `is_refund_required` (L1784–1803) only calls `env::promise_result_checked` when `is_ft_transfer_call` is `true`; for the `false` branch it returns `false` unconditionally (L1800–1803) with the comment "Not ft_transfer_call: don't refund." Consequently, when `ft_transfer` panics (promise result = `Failed`), the callback takes the `else` path (L1719–1746): it mints/transfers the fee to the relayer and emits `FinTransferEvent`. The revert path — `burn_tokens_if_needed`, `revert_lock_actions`, `remove_fin_transfer` (L1703–1718) — is never reached. Because `remove_fin_transfer` is never called, the transfer ID remains in `finalised_transfers` forever, making any retry impossible.

## Impact Explanation
This directly causes **permanent freezing of bridged funds**: the bridge contract retains the tokens (since the panicked `ft_transfer` rolled back the token movement), but `locked_tokens` accounting is already decremented and the transfer ID is permanently finalized, so there is no on-chain path to recover or redistribute the funds. This matches the allowed Critical impact: *permanent freezing of bridged funds*.

## Likelihood Explanation
No privileged access to the bridge is required. The trigger is entirely within the token contract's normal operation. USDC and USDT on NEAR implement operator-controlled blacklists and pause mechanisms that are exercised in real-world regulatory events. A recipient can be blacklisted between source-chain lock and NEAR finalization. Any relayer submitting a valid proof for such a transfer will trigger the bug. The condition is realistic, repeatable, and requires no victim mistake.

## Recommendation
In `is_refund_required` (or directly in `fin_transfer_send_tokens_callback`), check the promise result regardless of `is_ft_transfer_call`. When `is_ft_transfer_call` is `false`, call `env::promise_result_checked(0, …)` and treat an `Err` result as requiring a refund. This mirrors the existing revert path: call `burn_tokens_if_needed`, `revert_lock_actions`, `remove_fin_transfer`, and emit `FailedFinTransferEvent`. Alternatively, restructure `is_refund_required` to always inspect the promise result first, and only apply the `ft_transfer_call`-specific zero-amount check when `is_ft_transfer_call` is `true`.

## Proof of Concept
1. User locks 1000 USDC on Ethereum targeting a NEAR recipient.
2. Before the relayer submits the proof, the NEAR recipient is blacklisted by the USDC contract operator.
3. Relayer calls `fin_transfer` with a valid proof.
4. `process_fin_transfer_to_near` runs: `add_fin_transfer` marks the transfer finalized; `unlock_tokens_if_needed` decrements `locked_tokens[Eth][usdc.near]` by 1000 (L1875–1885).
5. `send_tokens` issues `ft_transfer(recipient, 1000)` to `usdc.near` (L2102–2106). The USDC contract panics — promise result is `Failed`.
6. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
7. `is_refund_required(false)` returns `false` at L1800–1803 without reading the promise result.
8. The `else` branch executes (L1719–1746): fee is transferred to the relayer; `FinTransferEvent` is emitted.
9. `remove_fin_transfer` is never called — the transfer ID is permanently in `finalised_transfers`. `locked_tokens[Eth][usdc.near]` is 0. The bridge holds 1000 USDC with no recovery path.

A local integration test can reproduce this by deploying a mock NEP-141 token whose `ft_transfer` panics unconditionally, submitting a valid `fin_transfer` proof targeting that token's recipient, and asserting post-callback that `finalised_transfers` still contains the transfer ID and the bridge token balance is unchanged.