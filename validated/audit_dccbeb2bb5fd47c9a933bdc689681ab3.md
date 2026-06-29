Audit Report

## Title
Fee Permanently Locked With No Recovery Path in Fast-Transfer Finalization to Foreign Chain - (File: near/omni-bridge/src/lib.rs)

## Summary
In `process_fin_transfer_to_other_chain`, when a fast transfer is detected, the function locks the fee via `lock_tokens_if_needed` for the destination chain, sends only `amount_without_fee` to the fast-transfer relayer, and calls `mark_fast_transfer_as_finalised` — but never stores the `TransferMessage` in `pending_transfers` and never pays the fee to anyone. The fee is permanently trapped in `locked_tokens` with no code path able to release it, corrupting the bridge's escrow accounting.

## Finding Description
`process_fin_transfer_to_other_chain` unconditionally locks the fee for the destination chain before branching on fast-transfer status:

```rust
// lines 2002-2006
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token,
    transfer_message.fee.fee.into(),
);
```

In the fast-transfer branch (lines 2028-2040), only `amount_without_fee` is sent to the relayer and the fast transfer is marked finalised, but no `add_transfer_message` call is made and no fee is paid:

```rust
if let Some(relayer) = recipient {
    self.send_tokens(token, relayer, U128(amount_without_fee), "").detach();
    self.mark_fast_transfer_as_finalised(&fast_transfer.id());
    // ← no add_transfer_message, no fee payment
}
```

The only recovery mechanism is `claim_fee_callback` (line 1094), which calls `self.remove_transfer_message(fin_transfer.transfer_id)`. Since the message was never stored, this call panics, making the locked fee permanently unrecoverable.

The non-fast-transfer branch (lines 2042-2044) correctly calls `add_transfer_message`, enabling a later `claim_fee` call. The analogous `process_fin_transfer_to_near` path (lines 1887-1901) correctly sets `fee_recipient = status.relayer` and pays the fee immediately. The "to-other-chain" fast-transfer path has no equivalent.

## Impact Explanation
This is a concrete, permanent loss of bridged funds held in escrow. Every fast-transfer finalization where the final destination is a foreign chain (Ethereum, Solana, Base, etc.) permanently locks the user-specified fee inside the bridge contract. The `locked_tokens` counter for the destination chain is inflated by the sum of all such lost fees, corrupting the bridge's escrow accounting. This matches the critical impact class: **fee mis-accounting and permanent freezing of bridged funds**.

## Likelihood Explanation
The fast-transfer-to-other-chain path is a standard, documented bridge operation requiring no special conditions or adversarial setup. Any trusted relayer executing a fast transfer whose recipient is a foreign-chain address triggers this path on every subsequent finalization. The bug fires deterministically on every normal execution of this flow.

## Recommendation
In the fast-transfer branch of `process_fin_transfer_to_other_chain`, immediately pay the fee to the appropriate recipient (mirroring the `process_fin_transfer_to_near` pattern). Specifically, after sending `amount_without_fee` to the relayer, call `send_fee_internal` (or an equivalent direct token transfer) for `transfer_message.fee.fee` to the fast-transfer relayer, and ensure `unlock_tokens_if_needed` is called for the destination chain to reverse the lock. Alternatively, store the transfer message via `add_transfer_message` so that `claim_fee` can be called later, though the immediate-payment approach is simpler and consistent with the to-NEAR path.

## Proof of Concept

1. User initiates a transfer: origin chain → NEAR → Ethereum, `amount = 1000`, `fee = 10`.
2. Fast-transfer relayer calls `ft_transfer_call` with `FastFinTransfer` message, sending 990 tokens to the bridge. Bridge records `fast_transfer` with `relayer = fast_relayer`.
3. Finalization relayer submits inbound proof via `fin_transfer`, routing to `process_fin_transfer_to_other_chain`.
4. Execution:
   - `lock_tokens_if_needed(Eth, token, 10)` — fee locked in `locked_tokens`.
   - Fast transfer detected → 990 sent to `fast_relayer`, fast transfer marked finalised.
   - Transfer message **not** stored in `pending_transfers`.
5. The 10-token fee is now locked in `locked_tokens[(Eth, token)]` with no stored transfer message.
6. Any call to `claim_fee` with a proof referencing this transfer ID will panic at `remove_transfer_message` (line 1094) because the entry does not exist.
7. The 10 tokens are permanently unrecoverable; `locked_tokens` is permanently inflated.