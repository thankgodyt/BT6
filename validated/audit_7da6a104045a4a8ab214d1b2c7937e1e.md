Audit Report

## Title
Detached Token Transfers With No Failure Callback Cause Permanent Relayer Fee Loss and Escrow Mis-Accounting — (`near/omni-bridge/src/lib.rs`)

## Summary

In `send_fee_internal`, the native-fee promise is `.detach()`-ed and `ClaimFeeEvent` is emitted synchronously before the token-fee cross-contract call is dispatched, with no failure callback on either. In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, `send_tokens(...).detach()` is called before state is permanently mutated and events are emitted. In all three paths, if the underlying token transfer fails (e.g., NEP-141 storage not registered, token contract paused), the relayer permanently loses their funds with no recovery path, and the bridge's locked-token accounting is left in an inconsistent state.

## Finding Description

**`send_fee_internal` (L2650–2701):**

`claim_fee_callback` at L1094 calls `remove_transfer_message`, permanently deleting the stored transfer. It then calls `send_fee_internal`. Inside `send_fee_internal`:

1. The native-fee branch (L2664–2673) calls `Promise::new(fee_recipient).transfer(...).detach()` or `ext_token::ext(...).mint(...).detach()` — both results are discarded.
2. `ClaimFeeEvent` is logged synchronously at L2677–2682, before any cross-contract call resolves.
3. The token-fee branch (L2686–2698) returns an `ext_token::ext(...).ft_transfer(...)` or `.mint(...)` as a bare `PromiseOrValue` with no `.then(callback)` chained. `claim_fee_callback` returns this directly with no failure handler.

If `ft_transfer` panics (e.g., recipient has no NEP-141 storage registration), the failed receipt is silently dropped. The transfer message is already gone, `ClaimFeeEvent` is already on-chain, and the relayer receives nothing.

**`process_fin_transfer_to_other_chain` (L1980–2054):**

When a fast transfer exists, `unlock_tokens_if_needed` is called at L1997–2001 (decrementing the locked-token counter), then `send_tokens(...).detach()` at L2029–2039 fires the reimbursement to the fast-transfer relayer with the result discarded, then `mark_fast_transfer_as_finalised` at L2040 permanently marks the entry as finalised, and finally `FinTransferEvent` is emitted at L2053. If `send_tokens` fails, the fast-transfer relayer's pre-funded tokens are permanently lost: the locked-token counter has already been decremented, the fast-transfer entry is finalised (no retry), and the event is on-chain.

**`utxo_fin_transfer_fast` (L2542–2558):**

`send_tokens(...).detach()` at L2542–2548 fires the relayer reimbursement with the result discarded, then `UtxoTransferEvent` is emitted at L2550–2558. The fast-transfer state was already mutated at L2530–2533 (`remove_fast_transfer` / `mark_fast_transfer_as_finalised`). Same permanent-loss outcome on failure.

**Why existing checks are insufficient:**

There are no guards ensuring the fee recipient has registered NEP-141 storage before the transfer is removed from state. The `#[trusted_relayer]` gate on `claim_fee` does not prevent the relayer from being a victim of their own unregistered storage. The `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast` paths have no access restriction on the triggering `fin_transfer` call — any caller can finalize a transfer and trigger the detached send to the fast-transfer relayer.

## Impact Explanation

This matches two allowed critical impact classes:

- **Loss of bridged/relayer funds**: The fast-transfer relayer pre-funds the transfer with their own tokens. If `send_tokens` fails silently, those tokens are permanently unrecoverable — `mark_fast_transfer_as_finalised` / `remove_fast_transfer` ensures no retry path exists.
- **Escrow mis-accounting**: `unlock_tokens_if_needed` decrements the locked-token counter before the detached transfer, so the bridge's internal accounting records tokens as unlocked even though they were never actually transferred to the recipient. This corrupts the locked-token invariant used to track bridged supply.

## Likelihood Explanation

The failure condition is directly reachable: NEP-141 requires `storage_deposit` before an account can receive tokens. A fast-transfer relayer who has not called `storage_deposit` on the specific bridged token contract will cause `ft_transfer` to panic and the receipt to fail silently. Relayers operating across many token types are realistically likely to miss storage registration for at least one token. Additionally, a token contract that is paused or that blacklists the relayer address produces the same silent failure through no action of the relayer. No privileged access is required to trigger the `fin_transfer` flow that calls `process_fin_transfer_to_other_chain`.

## Recommendation

1. Remove `.detach()` from all three sites. Chain the native-fee and token-fee promises together and add a `#[private]` callback that verifies both succeeded.
2. Move `env::log_str(ClaimFeeEvent / FinTransferEvent / UtxoTransferEvent)` into that callback so events are only emitted after confirmed success.
3. In the failure branch of the callback, re-insert the transfer message (or credit the fee to a claimable escrow) so the relayer can retry.
4. In `process_fin_transfer_to_other_chain` and `utxo_fin_transfer_fast`, call `mark_fast_transfer_as_finalised` / `remove_fast_transfer` and `unlock_tokens_if_needed` only inside the success branch of the callback, not before the detached send.

## Proof of Concept

**Fast-transfer relayer fund loss via `process_fin_transfer_to_other_chain`:**

1. Relayer R executes a fast transfer for token T, pre-funding the recipient. R has not called `storage_deposit` on token T's contract for their own account.
2. Any caller invokes `fin_transfer` for the corresponding cross-chain message.
3. `fin_transfer_callback` calls `process_fin_transfer_to_other_chain`. `unlock_tokens_if_needed` decrements the locked-token counter for T.
4. `send_tokens(T, R, amount, "").detach()` dispatches `ft_transfer(R, amount, None)`. Because R has no storage registration on T, the NEP-141 contract panics and the receipt fails silently.
5. `mark_fast_transfer_as_finalised` marks the entry as finalised. `FinTransferEvent` is emitted.
6. **Result**: R's pre-funded tokens are permanently lost. The locked-token counter for T is decremented even though no tokens moved. No retry is possible.

**Fee loss via `claim_fee` / `send_fee_internal`:**

1. Trusted relayer R calls `claim_fee` for a transfer with `token_fee > 0`. R has not registered storage for the bridged token.
2. `claim_fee_callback` calls `remove_transfer_message` (state permanently deleted), then `send_fee_internal`.
3. Native-fee `Promise::transfer(...).detach()` — result ignored.
4. `ClaimFeeEvent` logged on-chain.
5. `ft_transfer(R, token_fee, None)` dispatched. NEP-141 contract panics; receipt fails silently.
6. **Result**: Transfer message gone, `ClaimFeeEvent` on-chain, R receives neither native fee nor token fee.