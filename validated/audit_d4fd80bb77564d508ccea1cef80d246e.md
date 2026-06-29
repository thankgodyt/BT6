Audit Report

## Title
`is_refund_required` Treats `ft_transfer_call` Promise Panic as Success, Emitting `FinTransferEvent` With Permanently Lost Funds — (`near/omni-bridge/src/lib.rs`)

## Summary

`is_refund_required` returns `false` (no refund) when the underlying `ft_transfer_call` promise returns `Err` (i.e., the token contract panics and NEAR reverts the transfer). Both callers — `fin_transfer_send_tokens_callback` and `resolve_utxo_fin_transfer` — then emit a success event (`FinTransferEvent` / `UtxoTransferEvent`) even though the recipient received nothing. Because `add_fin_transfer` and `unlock_tokens_if_needed` execute before the callback, the transfer ID is permanently finalized and `locked_tokens` is permanently understated, with no recovery path.

## Finding Description

`is_refund_required` at `near/omni-bridge/src/lib.rs:1784–1804` is the sole gate controlling the refund vs. success branch:

```rust
Err(_) => false,   // promise panicked → treated as success (BUG)
```

and

```rust
} else {
    false           // non-U128 return → treated as success (BUG)
}
```

Both buggy branches cause the callers to take the success path.

**`fin_transfer_send_tokens_callback`** (line 1702): when `is_refund_required` returns `false`, it skips `revert_lock_actions` (line 1712), skips `remove_fin_transfer` (line 1714), and emits `FinTransferEvent` (line 1745).

**`resolve_utxo_fin_transfer`** (line 1025): same logic — skips removal and emits `UtxoTransferEvent` (lines 1032–1042).

The state mutations that cannot be undone happen *before* `send_tokens` is dispatched:
- `add_fin_transfer` at line 1875 permanently records the transfer ID as finalized.
- `unlock_tokens_if_needed` at lines 1881–1885 decrements `locked_tokens` for the origin chain/token pair.

`revert_lock_actions` (in `token_lock.rs:122–142`) re-locks the tokens by calling `lock_tokens` for each `Unlocked` action — but this is only reached when `is_refund_required` returns `true`. In the `Err` branch it is never called.

When `ft_transfer_call` panics, NEAR's state reversion means the recipient's balance is unchanged. The bridge has already decremented `locked_tokens` and finalized the transfer ID, so neither the accounting nor the finalization can be corrected.

## Impact Explanation

This concretely matches two allowed Critical impact classes:

1. **Loss of bridged funds**: the recipient receives nothing; the transfer ID is permanently finalized so no retry is possible; off-chain relayers observing `FinTransferEvent` mark the transfer complete. The user's funds are permanently lost.
2. **Escrow mis-accounting**: `locked_tokens` for the origin chain/token pair is decremented without a corresponding token delivery, permanently understating the bridge's escrow. This can cascade to allow subsequent transfers that should be blocked by the lock ceiling.

## Likelihood Explanation

The `ft_transfer_call` path is taken whenever the transfer message's `msg` field is non-empty (line 1973: `!msg.is_empty()`). The `msg` field is user-controlled from the source chain. Realistic triggers for a promise `Err`:

1. A registered token whose `ft_transfer_call` panics under specific conditions (custom transfer restrictions, fee-on-transfer tokens that revert when the bridge's balance is insufficient after fee deduction, tokens that panic when the recipient is a contract).
2. Gas exhaustion: `ft_transfer_call_gas` is computed dynamically and capped at `FT_TRANSFER_CALL_GAS`; if earlier operations in the same receipt consume gas, the allocated budget may be insufficient for the token contract's internal logic.
3. A token whose `ft_resolve_transfer` returns a non-`U128` JSON value hits the deserialization-failure branch.

Any unprivileged user who initiates a cross-chain transfer with a non-empty `msg` to a token exhibiting any of the above behaviors can trigger this. No special privileges are required.

## Recommendation

Treat both unexpected cases as requiring a refund, consistent with the `amount.0 == 0` case:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                match near_sdk::serde_json::from_slice::<U128>(&value) {
                    Ok(amount) => amount.0 == 0,
                    Err(_) => true,  // unexpected return → refund
                }
            }
            Err(_) => true,  // promise panicked → refund
        }
    } else {
        false
    }
}
```

This ensures that when `ft_transfer_call` fails for any reason, `revert_lock_actions` is called (restoring `locked_tokens`), `remove_fin_transfer` is called (allowing retry), and `FailedFinTransferEvent` is emitted instead of `FinTransferEvent`.

## Proof of Concept

1. Deploy a NEP-141 token whose `ft_transfer_call` panics when called with a non-empty `msg` (e.g., it validates `msg` content and panics on unexpected input).
2. Register this token with the bridge via the normal token registration path.
3. From the source EVM chain, initiate a cross-chain transfer with a non-empty `msg` field targeting this token on NEAR.
4. A relayer calls `fin_transfer` on NEAR → `process_fin_transfer_to_near` → `add_fin_transfer` (transfer ID finalized) → `unlock_tokens_if_needed` (`locked_tokens` decremented) → `send_tokens` → `ft_transfer_call` (panics, NEAR reverts token state) → `fin_transfer_send_tokens_callback`.
5. `is_refund_required` reads `Err` from `promise_result_checked` and returns `false`.
6. `FinTransferEvent` is emitted; `revert_lock_actions` is never called; `remove_fin_transfer` is never called.
7. The recipient's balance is unchanged. `locked_tokens` is permanently understated. The transfer ID cannot be retried. Funds are permanently lost.

A local integration test can reproduce this by mocking a token contract that panics in `ft_transfer_call` and asserting that after the callback: (a) `FinTransferEvent` is emitted, (b) `get_locked_tokens` returns the decremented value, and (c) `fin_transfer` with the same transfer ID panics with a duplicate-finalization error.