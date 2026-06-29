Audit Report

## Title
Fast-Transfer-to-NEAR Callback Records State After Cross-Contract Call, Enabling Double-Spending via Race with `fin_transfer` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
In `fast_fin_transfer`, when the recipient is a NEAR address, `add_fast_transfer` is not called synchronously — it is deferred to `fast_fin_transfer_to_near_callback` after a cross-contract call to `check_or_pay_ft_storage`. During the multi-block window before the callback executes, `fin_transfer` can be called with a valid proof, find no entry in `fast_transfers`, and pay the original recipient. When the callback subsequently executes, `add_fast_transfer` succeeds because `fin_transfer` only writes to `finalised_transfers` (not `fast_transfers`), and the relayer's fronted tokens are also sent to the recipient — resulting in a concrete double-spend.

## Finding Description

**`fast_fin_transfer` (NEAR recipient branch, L778–827):**
The only synchronous guard is `is_unified_transfer_finalised`, which checks `finalised_transfers` and `finalised_utxo_transfers` — not `fast_transfers`. No entry is written to `fast_transfers` at this point. The function issues a cross-contract call to `check_or_pay_ft_storage` and chains `fast_fin_transfer_to_near_callback` as a subsequent receipt.

**`fast_fin_transfer_to_near_callback` (L838–893):**
`add_fast_transfer` is called here — this is the first and only write to `fast_transfers`. There is no guard checking `is_unified_transfer_finalised` before this call. If `fin_transfer` has already settled the transfer, the callback still proceeds to insert into `fast_transfers` and send the relayer's tokens to the recipient.

**`process_fin_transfer_to_near` (L1875–1902):**
`add_fin_transfer` inserts the transfer ID into `finalised_transfers` (L1875). It then reads `fast_transfers` via `get_fast_transfer_status` (L1879). If the callback has not yet executed, `fast_transfer_status` is `None`, and tokens are sent to the original recipient rather than the relayer (L1897–1901).

**`add_fast_transfer` (L2246–2268):**
The only guard is `fast_transfers.insert(...).is_none()` — it rejects a duplicate key in `fast_transfers` only. It does not cross-check `finalised_transfers`. Because `fin_transfer` never writes to `fast_transfers`, the callback's `add_fast_transfer` call succeeds even after `fin_transfer` has already settled the same transfer.

**Why existing checks fail:**
- `is_unified_transfer_finalised` in `fast_fin_transfer` runs before the callback window opens — it cannot detect a future `fin_transfer` call.
- `add_fast_transfer` in the callback has no guard against `finalised_transfers`.
- `add_fin_transfer` in `fin_transfer` prevents replay of `fin_transfer` itself but does not prevent the callback from subsequently executing.

## Impact Explanation
This is a concrete double-spend of bridged funds, matching the Critical impact class "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds." For bridged tokens, `fin_transfer` mints/unlocks tokens to the recipient (1×); the callback then transfers the relayer's own tokens to the same recipient (2×). The relayer permanently loses their fronted liquidity with no reimbursement. The recipient gains double the bridged amount from a single source-chain transfer.

## Likelihood Explanation
The race window spans at least one NEAR block (~1 second) between the `fast_fin_transfer` receipt and the `fast_fin_transfer_to_near_callback` receipt. `fin_transfer` is callable by any party holding a valid proof; the proof is derived from a public source-chain transaction and is available immediately after the source-chain event is finalized. No special privilege beyond holding the proof is required. The attack is deterministic: once the relayer's fast-transfer transaction is observed on-chain, an attacker submits `fin_transfer` in the immediately following block.

## Recommendation
**Option A (preferred):** In `fast_fin_transfer_to_near_callback`, add a guard before `add_fast_transfer`:
```rust
if self.is_unified_transfer_finalised(&fast_transfer.transfer_id) {
    // fin_transfer already settled; refund relayer's tokens
    return self.send_tokens(fast_transfer.token_id, relayer_id, amount_without_fee, "");
}
```
**Option B:** Move `add_fast_transfer` into `fast_fin_transfer` itself (before the cross-contract call), and revert it in the callback if `check_or_pay_ft_storage` fails. This eliminates the window entirely by making the state write atomic with the initial call.

## Proof of Concept
1. Source-chain transfer with nonce `N` is initiated; proof `P` is publicly available.
2. Trusted relayer calls `ft_transfer_call(bridge, amount, FastFinTransferMsg{nonce: N, recipient: Near("alice"), ...})`.
   - `fast_fin_transfer` executes synchronously; `fast_transfers` remains empty; `check_or_pay_ft_storage` receipt is queued.
3. In the next block, attacker calls `fin_transfer({proof: P, storage_deposit_actions: [{alice, token}]})`.
   - `add_fin_transfer` inserts `(chain, N)` into `finalised_transfers` (L1875).
   - `get_fast_transfer_status` returns `None` because `fast_transfers` is still empty (L1879).
   - Tokens are minted/unlocked and sent to `alice` (1×) via the `None` branch (L1897–1901).
4. `fast_fin_transfer_to_near_callback` executes.
   - `add_fast_transfer` succeeds: `fast_transfers.insert(...).is_none()` is true because `fin_transfer` never wrote to `fast_transfers` (L2253–2264).
   - `send_tokens` sends relayer's tokens to `alice` (2×) (L877–882).
5. Result: `alice` holds 2× tokens; relayer holds 0 tokens and receives no reimbursement.