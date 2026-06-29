Audit Report

## Title
Fast-Transfer-to-NEAR Callback Records State After Cross-Contract Call, Enabling Double-Spending via Race with `fin_transfer` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
In `fast_fin_transfer`, when the recipient is a NEAR address, the bridge defers the `add_fast_transfer` state write to the asynchronous `fast_fin_transfer_to_near_callback`. During the multi-block window before the callback executes, any party holding a valid proof can call `fin_transfer`, which reads `fast_transfers` (still empty), finds no fast transfer, and pays the original recipient. When the callback subsequently executes, `add_fast_transfer` succeeds because `fast_transfers` is still empty, and the relayer's tokens are also sent to the recipient — resulting in a double payment.

## Finding Description
**Root cause — deferred state write in the NEAR recipient branch of `fast_fin_transfer`:**

At L778–780, `fast_fin_transfer` checks `is_unified_transfer_finalised` (which reads `finalised_transfers` and `finalised_utxo_transfers`) and panics if the transfer is already finalised. However, no entry is written to `fast_transfers` at this point. For a NEAR recipient, the function issues a cross-contract call to `check_or_pay_ft_storage` and chains `fast_fin_transfer_to_near_callback` as a subsequent receipt (L812–827). The `add_fast_transfer` call — the only write to `fast_transfers` — is deferred to the callback at L854–856.

**The callback contains no guard against `finalised_transfers`:**

`fast_fin_transfer_to_near_callback` (L838–893) calls `add_fast_transfer` (L854) without first checking `is_unified_transfer_finalised`. `add_fast_transfer` itself (L2246–2268) only rejects a duplicate key in `fast_transfers`; it does not consult `finalised_transfers`.

**`fin_transfer` path reads `fast_transfers` while it is still empty:**

`process_fin_transfer_to_near` (L1875) first calls `add_fin_transfer`, inserting the transfer ID into `finalised_transfers`. It then calls `get_fast_transfer_status` (L1879) on `fast_transfers`. If `fast_transfers` has no entry (because the callback has not yet executed), `fast_transfer_status` is `None`, and the bridge sends tokens to the original recipient (L1897–1901) rather than the relayer.

**Exploit sequence:**
1. Trusted relayer calls `ft_transfer_call` → `fast_fin_transfer` executes; `fast_transfers` is empty; `check_or_pay_ft_storage` receipt is queued.
2. In the next block, attacker calls `fin_transfer` with a valid proof. `add_fin_transfer` inserts `T` into `finalised_transfers`. `get_fast_transfer_status` returns `None` → tokens sent to recipient (1×).
3. `fast_fin_transfer_to_near_callback` executes. `add_fast_transfer` succeeds (no entry in `fast_transfers`). `send_tokens` sends relayer's tokens to recipient (2×).
4. Recipient holds 2× tokens; relayer holds 0 tokens and receives no reimbursement.

**Why existing checks are insufficient:**
- The `is_unified_transfer_finalised` check in `fast_fin_transfer` (L778) runs before `fin_transfer` has been called, so it cannot prevent the race.
- `add_fast_transfer` (L2253–2264) only checks for a duplicate key in `fast_transfers`; since `fin_transfer` never writes to `fast_transfers`, the callback's insert succeeds unconditionally after `fin_transfer` has already settled the transfer.
- The `FastTransferAlreadyPerformed` guard in `add_fast_transfer` is therefore bypassed entirely in this race scenario.

## Impact Explanation
This is a concrete double-spend of bridged funds. For bridged tokens, `fin_transfer` mints or unlocks tokens to the recipient; the callback then transfers the relayer's own tokens to the same recipient. The recipient holds 2× the bridged amount for a single source-chain transfer. The relayer permanently loses their fronted liquidity with no reimbursement path. This matches the Critical allowed impact: "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds."

## Likelihood Explanation
- The race window spans at least one NEAR block (~1 second) between the `fast_fin_transfer` receipt and the `fast_fin_transfer_to_near_callback` receipt.
- `fin_transfer` is callable by any party holding a valid proof; the proof is derived from a public source-chain transaction and is available immediately after the source-chain event is finalized.
- No special privilege is required beyond holding the proof. The attacker simply observes the relayer's fast-transfer transaction on-chain and submits `fin_transfer` in the immediately following block.
- The attack is deterministic and repeatable for every fast transfer targeting a NEAR address.

## Recommendation
**Option A (preferred):** In `fast_fin_transfer_to_near_callback`, add a guard before `add_fast_transfer`:
```rust
if self.is_unified_transfer_finalised(&fast_transfer.transfer_id) {
    // fin_transfer already settled; refund relayer's tokens
    return self.send_tokens(fast_transfer.token_id, relayer_id, amount_without_fee, "");
}
```
**Option B:** Move `add_fast_transfer` into `fast_fin_transfer` itself (before the cross-contract call), and revert it in the callback if `check_or_pay_ft_storage` fails. This eliminates the window entirely by making the state write synchronous.

## Proof of Concept
1. Source-chain transfer with nonce `N` is initiated; proof `P` is available on-chain.
2. Trusted relayer calls `ft_transfer_call(bridge, amount, FastFinTransferMsg{nonce: N, recipient: Near("alice"), ...})`. `fast_fin_transfer` executes; `fast_transfers` is empty; `check_or_pay_ft_storage` receipt is queued.
3. In the next block, attacker calls `fin_transfer({proof: P, storage_deposit_actions: [{alice, token}]})`. `add_fin_transfer` inserts `(chain, N)` into `finalised_transfers`. `get_fast_transfer_status` returns `None` → tokens minted/unlocked and sent to `alice` (1×).
4. `fast_fin_transfer_to_near_callback` executes. `add_fast_transfer` succeeds (no entry in `fast_transfers`). `send_tokens` sends relayer's tokens to `alice` (2×).
5. Result: `alice` holds 2× tokens; relayer holds 0 tokens and receives no reimbursement.

A local integration test can reproduce this by: (a) calling `fast_fin_transfer` on a mock token contract, (b) advancing one block, (c) calling `fin_transfer` with a valid proof before the callback resolves, and (d) asserting that the recipient's balance equals 2× the bridged amount and the relayer's balance is 0.