Audit Report

## Title
`is_refund_required` Treats `ft_transfer_call` Promise Panic as Success, Emitting `FinTransferEvent` on Failed Token Delivery — (`near/omni-bridge/src/lib.rs`)

## Summary

`is_refund_required` returns `false` (no refund needed) when the underlying `ft_transfer_call` promise returns `Err` — i.e., when the token contract panics before completing the transfer. Both `fin_transfer_send_tokens_callback` and `resolve_utxo_fin_transfer` then proceed to the success branch, emitting `FinTransferEvent` / `UtxoTransferEvent` even though the recipient received nothing. Because the transfer ID was already finalized and `locked_tokens` already decremented before the callback runs, the state is permanently corrupted with no recovery path.

## Finding Description

`is_refund_required` at lines 1784–1804 of `near/omni-bridge/src/lib.rs` is the sole gate controlling whether a failed `ft_transfer_call` triggers a refund or a success event:

```rust
Err(_) => false,   // promise panicked → treated as success (BUG)
```

and

```rust
} else {
    false           // non-U128 return → treated as success (BUG)
}
```

Both branches return `false`, meaning "no refund required," which routes both callers into the success path.

**`fin_transfer_send_tokens_callback`** (lines 1702–1746): when `is_refund_required` returns `false`, it skips `revert_lock_actions` and `remove_fin_transfer`, and instead emits `FinTransferEvent`.

**`resolve_utxo_fin_transfer`** (lines 1016–1044): when `is_refund_required` returns `false`, it emits `UtxoTransferEvent` and returns `U128(0)`, without removing the fin-transfer record.

Critically, both `add_fin_transfer` (line 1875) and `unlock_tokens_if_needed` (lines 1881–1885) execute inside `process_fin_transfer_to_near` *before* the `send_tokens` promise chain is dispatched. These state changes are committed to NEAR storage before the callback runs. When `ft_transfer_call` panics, NEAR reverts only the token contract's state changes — the bridge's own accounting changes (transfer ID finalized, `locked_tokens` decremented) are permanent.

The `is_ft_transfer_call` flag is set at line 1973 as `!msg.is_empty()`, so this path is taken for any finalization with a non-empty `msg` field. `send_tokens` dispatches `ft_transfer_call` at lines 2113–2116 for non-deployed tokens with a non-empty `msg`, and calls `mint` (which internally calls `ft_transfer_call`) at lines 2094–2101 for deployed tokens with a non-empty `msg`.

## Impact Explanation

This matches two allowed critical impact classes:

1. **Loss of bridged funds**: For deployed tokens, the mint+`ft_transfer_call` panics — no tokens are ever created for the recipient. The transfer ID is finalized; no retry is possible. The user's cross-chain transfer is permanently lost.

2. **Escrow mis-accounting**: For non-deployed (locked) tokens, `ft_transfer_call` panics and NEAR reverts the token transfer — tokens remain in the bridge contract. However, `locked_tokens` is decremented without a corresponding delivery, permanently understating the bridge's escrow obligations for that chain/token pair. The transfer ID is finalized, so the user cannot recover their funds.

In both cases, `FinTransferEvent` / `UtxoTransferEvent` is emitted, causing off-chain relayers and indexers to mark the transfer complete, with no on-chain mechanism to recover the user's funds.

## Likelihood Explanation

The `ft_transfer_call` path is triggered for any finalization where `transfer_message.msg` is non-empty — a standard feature of the bridge protocol for DeFi integrations. Realistic triggers for a promise panic include:

1. A registered token whose `ft_transfer_call` panics under specific conditions (custom transfer restrictions, fee-on-transfer tokens that revert when bridge balance is insufficient after fee deduction, tokens that reject contract recipients).
2. Gas exhaustion: `ft_transfer_call_gas` is computed dynamically (line 2063–2067) as remaining gas minus several fixed overheads. If earlier operations consume more gas than expected, the allocated budget may be insufficient for the token contract's internal logic.
3. A token whose `ft_resolve_transfer` returns a non-`U128` JSON value hits the deserialization-failure branch.

Any external user initiating a cross-chain transfer with a non-empty `msg` to a token exhibiting any of the above behaviors can trigger this condition. No special privileges are required.

## Recommendation

Treat both unexpected cases as requiring a refund, consistent with the `amount.0 == 0` case:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                match near_sdk::serde_json::from_slice::<U128>(&value) {
                    Ok(amount) => amount.0 == 0,
                    Err(_) => true,  // unexpected return → treat as failure, refund
                }
            }
            Err(_) => true,  // promise panicked → treat as failure, refund
        }
    } else {
        false
    }
}
```

This ensures that when `ft_transfer_call` fails for any reason, `revert_lock_actions` is called, the fin-transfer record is removed (allowing retry), and `FailedFinTransferEvent` is emitted instead of `FinTransferEvent`.

## Proof of Concept

1. Deploy a NEP-141 token contract whose `ft_transfer_call` panics when called with a non-empty `msg` (e.g., it validates `msg` format and panics on unexpected content).
2. Register this token with the bridge via the standard `deploy_token` / `bind_token` path.
3. Initiate a cross-chain transfer from EVM to NEAR with a non-empty `msg` field targeting this token.
4. A relayer calls `fin_transfer` on NEAR → `process_fin_transfer_to_near` runs → `add_fin_transfer` (line 1875) and `unlock_tokens_if_needed` (lines 1881–1885) commit state → `send_tokens` dispatches `ft_transfer_call` (lines 2113–2116).
5. The token contract panics; NEAR reverts the token transfer state.
6. `fin_transfer_send_tokens_callback` is invoked → `is_refund_required` returns `false` (line 1798) → success branch taken → `FinTransferEvent` emitted (line 1745).
7. Observable outcome: recipient balance unchanged; transfer ID permanently finalized; `locked_tokens` understated; no recovery path exists.

A local integration test can reproduce this by deploying a mock NEP-141 token that panics in `ft_transfer_call` when `msg` is non-empty, then calling `fin_transfer` with a non-empty `msg` and asserting that `FinTransferEvent` is emitted while the recipient's balance remains zero.