Let me look at a few more details to complete the validation.

Audit Report

## Title
Unhandled `ft_transfer` Failure in `fin_transfer_send_tokens_callback` Permanently Locks Bridged Tokens — (File: `near/omni-bridge/src/lib.rs`)

## Summary
When `process_fin_transfer_to_near` finalizes a cross-chain transfer to a NEAR recipient with an empty `msg`, `send_tokens` issues a plain `ft_transfer`. The callback `fin_transfer_send_tokens_callback` delegates failure detection entirely to `is_refund_required`, which unconditionally returns `false` when `is_ft_transfer_call = false`, never inspecting the promise result. If `ft_transfer` fails for any reason, `revert_lock_actions` and `remove_fin_transfer` are never called, permanently decrementing `locked_tokens` and recording the transfer as finalized while the tokens remain stranded in the bridge contract.

## Finding Description
`process_fin_transfer_to_near` executes three irreversible state mutations before the cross-contract `ft_transfer` result is known:

1. `add_fin_transfer` records the transfer ID in `finalised_transfers` (line 1875).
2. `unlock_tokens_if_needed` decrements `locked_tokens` for the origin chain (lines 1881–1885).
3. `send_tokens` issues a plain `ft_transfer` when `msg` is empty and the token is neither a deployed token nor wNEAR (lines 2102–2106), then chains `fin_transfer_send_tokens_callback` with `is_ft_transfer_call = !msg.is_empty()` → `false` (line 1973).

Inside the callback, `is_refund_required(false)` hits the `else` branch and returns `false` unconditionally without reading `env::promise_result_checked`:

```rust
// near/omni-bridge/src/lib.rs:1800-1803
} else {
    // Not ft_transfer_call: don't refund
    false
}
```

Because `is_refund_required` returns `false`, the callback always takes the success branch (lines 1719–1746), dispatching fees and emitting `FinTransferEvent`. The recovery branch — `revert_lock_actions` (line 1712) and `remove_fin_transfer` (line 1714) — is never reached regardless of whether `ft_transfer` succeeded or failed.

`revert_lock_actions` for an `Unlocked` action calls `lock_tokens` to restore the counter (token_lock.rs lines 132–138). Without it, `locked_tokens` is permanently understated and the transfer ID remains in `finalised_transfers`, blocking any replay.

## Impact Explanation
This directly causes **permanent freezing of bridged funds**: the bridge holds the actual token balance but has no accounting entry pointing to it, the `locked_tokens` invariant is corrupted (understated), and the transfer ID is consumed so the finalization cannot be retried. This matches the Critical impact class: *permanent freezing of bridged funds across NEAR flows*.

## Likelihood Explanation
The attacker-controlled path requires only standard NEAR account operations. The attacker registers storage for the target token (satisfying the storage check in `process_fin_transfer_to_near`), initiates a cross-chain transfer to their NEAR account with empty `msg`, and after the relayer's `fin_transfer_callback` passes the storage check but before the `ft_transfer` receipt is processed (a different block in NEAR's async execution model), calls `storage_unregister` on the token contract while holding a zero balance. The `ft_transfer` receipt then fails, but the callback takes the success path. No privileged access is required; the attacker only needs to control the recipient NEAR account. A non-adversarial path also exists: any transient failure of the NEP-141 token contract (pause, bug, out-of-gas) during `ft_transfer` produces the same permanent lock.

## Recommendation
`is_refund_required` must also inspect the promise result for plain `ft_transfer`. The simplest fix is to check `env::promise_result_checked(0, ...)` in the `else` branch and return `true` on `Err`:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        // existing ft_transfer_call logic
        ...
    } else {
        // Plain ft_transfer: treat any promise failure as requiring revert
        env::promise_result_checked(0, 0).is_err()
    }
}
```

Alternatively, add a `#[callback_result]` parameter to `fin_transfer_send_tokens_callback` and call `revert_lock_actions` + `remove_fin_transfer` whenever the result is `Err`, regardless of `is_ft_transfer_call`.

## Proof of Concept
1. Token `T` is a non-deployed NEP-141 token bridged from Ethereum; bridge holds `N` units in `locked_tokens[(Eth, T)] = N`.
2. Attacker controls NEAR account `R`; calls `storage_deposit` on `T`'s contract to register `R` (balance = 0).
3. Attacker initiates a transfer of `N` tokens from Ethereum to `R` with empty `msg`.
4. Relayer calls `fin_transfer` → `fin_transfer_callback` → storage balance check passes → `process_fin_transfer_to_near` runs:
   - `add_fin_transfer(transfer_id)` → transfer recorded as finalized.
   - `unlock_tokens_if_needed(Eth, T, N)` → `locked_tokens[(Eth, T)]` decremented to 0.
   - `send_tokens(T, R, N, "")` → plain `ft_transfer` scheduled.
5. Before the `ft_transfer` receipt executes (next block), attacker calls `storage_unregister` on `T`'s contract (balance is 0, so it succeeds).
6. `ft_transfer` receipt executes → fails (no storage for `R`).
7. `fin_transfer_send_tokens_callback` runs with `is_ft_transfer_call = false` → `is_refund_required` returns `false` → success branch taken → `FinTransferEvent` emitted.
8. Result: `locked_tokens[(Eth, T)] = 0`, transfer ID consumed, `N` tokens stranded in bridge contract with no recovery path.

A local integration test can reproduce this by mocking the `ft_transfer` promise result as `PromiseResult::Failed` and asserting that `locked_tokens` is restored and `finalised_transfers` does not contain the transfer ID — both assertions will fail against the current code.