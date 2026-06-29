Audit Report

## Title
`is_refund_required` Returns `false` on Protocol-Level `ft_transfer_call` Failure, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`is_refund_required` at line 1798 returns `false` when `env::promise_result_checked` yields `Err(_)`, which occurs when the underlying `ft_transfer_call` fails at the NEAR protocol level (token contract panic, gas exhaustion, access-control rejection). All three callbacks that depend on this function — `fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, and `resolve_utxo_fin_transfer` — then proceed down the "success" path. Because the bridge's state mutations (`add_fin_transfer`, `unlock_tokens_if_needed`) were committed in the prior transaction, the transfer is permanently finalized with no token delivery and no recovery path.

## Finding Description

`is_refund_required` (lines 1784–1804) distinguishes two outcomes of a `ft_transfer_call` promise:

```
Ok(value) → parse U128 used-amount → refund iff used == 0
Err(_)    → "Unexpected case: don't refund" → false   ← bug
```

In NEAR's async execution model, a promise result is `Err` when the callee panics before returning a value — for example, the token contract is paused, an invariant check fires, or the `ft_transfer_call → ft_on_transfer → ft_resolve_transfer` gas budget is exhausted. In all such cases the NEAR runtime reverts the token transfer (tokens return to the bridge's balance), but `is_refund_required` returns `false`.

`process_fin_transfer_to_near` (lines 1868–1978) commits two irreversible state mutations **before** dispatching `send_tokens`:
1. `add_fin_transfer` inserts the transfer ID into `finalised_transfers` (line 1875).
2. `unlock_tokens_if_needed` decrements `locked_tokens` (line 1881).

When `fin_transfer_send_tokens_callback` (lines 1692–1747) is invoked and `is_refund_required` returns `false`, it skips `revert_lock_actions`, `remove_fin_transfer`, and `burn_tokens_if_needed`, and instead emits `FinTransferEvent`. The transfer ID is permanently in `finalised_transfers` (replay is impossible), `locked_tokens` is permanently under-counted, and the tokens sit in the bridge's own balance with no admin recovery function.

The same logic flaw affects `resolve_fast_transfer` (lines 895–912) — `burn_tokens_if_needed` fires unconditionally, then `is_refund_required` returns `false`, so the fast-transfer record is not removed and the relayer receives no refund — and `resolve_utxo_fin_transfer` (lines 1014–1044), where the UTXO transfer is logged as successful while tokens were never delivered.

The gas cap computation at lines 2063–2067 dynamically caps `ft_transfer_call_gas` at `FT_TRANSFER_CALL_GAS`; a receiver contract that consumes more gas than this cap causes the entire sub-tree to fail with `Err`, directly triggering the bug.

## Impact Explanation

Permanent freezing of bridged funds: the user's tokens are irrecoverably locked in the bridge contract. The transfer ID cannot be replayed (it is in `finalised_transfers`), `locked_tokens` accounting is permanently wrong (under-counted by the transfer amount), and no admin or DAO function exists to recover the stranded balance. This matches the Critical impact class: "permanent freezing of bridged funds."

## Likelihood Explanation

Any unprivileged user who specifies a non-empty `msg` in a cross-chain inbound transfer (to invoke a DeFi protocol on NEAR) is on the affected code path. Realistic triggers requiring no special access:
- A DEX or lending protocol whose `ft_on_transfer` consumes more gas than `FT_TRANSFER_CALL_GAS` (gas exhaustion → `Err`).
- A token contract with a pause mechanism or access-control check on `ft_transfer_call` (contract panic → `Err`).
- A token contract upgraded mid-flight that changes its internal invariants.

No admin compromise, MPC collusion, or validator attack is required.

## Recommendation

Change the `Err` arm of `is_refund_required` to return `true`:

```rust
// Protocol-level failure: tokens were not delivered; revert bridge state.
Err(_) => true,
```

This ensures all three callbacks correctly invoke `revert_lock_actions`, `remove_fin_transfer` / `remove_fast_transfer`, and emit `FailedFinTransferEvent` when `ft_transfer_call` fails at the protocol level.

## Proof of Concept

1. User initiates a cross-chain transfer from Ethereum to NEAR with `msg = "<dex-swap-payload>"` (non-empty), bridging 1000 USDC.
2. Relayer submits proof via `fin_transfer`. `process_fin_transfer_to_near` runs:
   - `add_fin_transfer` inserts the transfer ID into `finalised_transfers`.
   - `unlock_tokens_if_needed` decrements `locked_tokens[USDC]` by 1000.
   - `send_tokens` dispatches `ft_transfer_call(dex_contract, 1000, msg)` with gas capped at `FT_TRANSFER_CALL_GAS`.
3. The DEX contract's `ft_on_transfer` exhausts the allocated gas. The entire `ft_transfer_call` sub-tree fails; NEAR reverts the token transfer (1000 USDC returns to bridge balance). Promise result is `Err`.
4. `fin_transfer_send_tokens_callback` is invoked. `is_refund_required(true)` calls `env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT)` → `Err(_)` → returns `false`.
5. Callback takes the `else` branch: emits `FinTransferEvent`, sends fee to relayer. No state revert.
6. Transfer ID is permanently in `finalised_transfers`. `locked_tokens[USDC]` is 1000 lower than actual bridge balance. User's 1000 USDC is permanently frozen in the bridge contract.

A local integration test can reproduce this by deploying a mock token contract whose `ft_transfer_call` panics unconditionally, submitting a `fin_transfer` with a non-empty `msg`, and asserting that after the callback: (a) `finalised_transfers` contains the transfer ID, (b) `locked_tokens` is decremented, and (c) the bridge's token balance equals the pre-transfer balance (tokens never left).