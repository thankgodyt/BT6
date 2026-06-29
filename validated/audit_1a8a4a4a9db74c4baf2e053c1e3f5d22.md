Audit Report

## Title
Inverted Refund Condition in `is_refund_required` Causes Escrow Mis-Accounting and Unauthorized Token Minting — (File: near/omni-bridge/src/lib.rs)

## Summary
`is_refund_required` returns `true` when `ft_on_transfer` returns `0`, but under NEP-141 a return value of `0` means the receiver accepted all tokens and no refund is warranted. The condition is inverted: every successful `ft_transfer_call` delivery triggers the failure path, and every failed delivery triggers the success path. This corrupts locked-token accounting for native tokens and enables unrecorded minted supply for deployed tokens on every `fin_transfer` that carries a non-empty `msg`.

## Finding Description
The function at lines 1784–1804 reads the promise result of `ft_on_transfer` and returns `true` when `amount.0 == 0`:

```rust
// near/omni-bridge/src/lib.rs L1791
amount.0 == 0   // ← inverted: 0 means "all accepted", not "refund needed"
```

Under NEP-141, `ft_on_transfer` returns the **amount to refund** (unused tokens). A return of `0` means the receiver consumed everything; a return of `N > 0` means N tokens were rejected and should be refunded. The correct predicate is `amount.0 != 0`.

**Path 1 — `fin_transfer_send_tokens_callback` (L1702–1718):**
When a recipient's `ft_on_transfer` returns `"0"` (standard success), `is_refund_required` returns `true` and the bridge:
1. Calls `burn_tokens_if_needed` — silently fails for deployed tokens because the bridge holds no balance after minting to the recipient.
2. Calls `revert_lock_actions` — re-increments `locked_tokens` even though the tokens have already left escrow.
3. Calls `remove_fin_transfer` — **deletes the nonce record**, making the transfer ID available for replay.
4. Emits `FailedFinTransferEvent`.

The recipient retains the minted/unlocked tokens while the bridge records the transfer as failed.

**Path 2 — `resolve_fast_transfer` (L906–911):**
When a relayer's `ft_on_transfer` returns `"0"` (accepted), `is_refund_required` returns `true`, `remove_fast_transfer` is called, and the full `amount` is returned to the token contract as a refund signal, breaking relayer settlement.

The comment at L1789–1790 ("refund if the used token amount is zero") confirms the developer confused the return value semantics: `ft_on_transfer` returns tokens-to-refund, not tokens-used.

## Impact Explanation
**Deployed (bridge) tokens — unauthorized minting / token supply inflation:**
Tokens are minted to the recipient via `ft_transfer_call`. The recipient's `ft_on_transfer` returns `"0"` (success). The bridge incorrectly enters the failure branch, `burn_tokens_if_needed` silently fails (bridge holds no tokens), and `remove_fin_transfer` deletes the nonce. The recipient holds the minted tokens with no corresponding burn recorded. Because the nonce record is deleted, the same MPC-signed proof can be re-submitted to finalize the transfer again, minting a second batch of tokens against the same origin-chain collateral — **unbounded unauthorized minting**.

**Native (locked) tokens — escrow mis-accounting enabling future unauthorized releases:**
Tokens are unlocked and sent to the recipient. `revert_lock_actions` then re-increments `locked_tokens` for an amount that has already left escrow. The bridge's ledger shows phantom locked balance. Subsequent `fin_transfer` calls can draw against this phantom balance, releasing tokens that were never deposited — **escrow mis-accounting enabling unauthorized fund release**.

Both impacts match the Critical allowed scope: unauthorized minting of bridged funds and balance/escrow mis-accounting that changes protocol balances.

## Likelihood Explanation
The bug fires on **every** `fin_transfer` where `transfer_message.msg` is non-empty (causing `ft_transfer_call` instead of plain `ft_transfer`) and the recipient contract correctly returns `"0"` from `ft_on_transfer`. This is the standard NEP-141 success response used by every compliant DeFi integration. No privileged access, no attacker-controlled input, and no victim mistake is required — normal bridge usage with any message-bearing transfer is sufficient to trigger the failure path. The condition is deterministic and repeatable across every such transfer.

## Recommendation
Invert the comparison in `is_refund_required`:

```rust
// Before (wrong):
amount.0 == 0

// After (correct):
amount.0 != 0
```

A non-zero return from `ft_on_transfer` means unused tokens exist and a refund is warranted. Zero means full acceptance and no refund is needed. Additionally, add a unit test that sets the promise result to `U128(0)` and asserts `is_refund_required` returns `false`, and a second test with `U128(N)` asserting it returns `true`.

## Proof of Concept
1. Deploy a bridge token (deployed token path) and register a recipient contract whose `ft_on_transfer` always returns `"0"`.
2. Submit a valid MPC-signed `fin_transfer` proof with a non-empty `msg` field.
3. The bridge calls `ft_transfer_call(recipient, amount, msg)`, minting `amount` tokens to the recipient.
4. The recipient's `ft_on_transfer` returns `"0"`.
5. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = true`; promise result is `U128(0)`.
6. `is_refund_required` evaluates `0 == 0 → true`, entering the failure branch.
7. `burn_tokens_if_needed` is called but silently fails (bridge holds no tokens).
8. `remove_fin_transfer` deletes the nonce record.
9. `FailedFinTransferEvent` is emitted.
10. Re-submit the identical proof — the nonce record is gone, so the bridge processes it again and mints a second `amount` to the recipient.
11. Repeat to inflate token supply without bound.

For the native-token escrow path: replace step 1 with a native token transfer; after step 9, query `get_locked_tokens` and observe it has been re-incremented to the pre-transfer value despite the tokens having been released, then submit a second `fin_transfer` against the phantom balance.