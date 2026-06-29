Audit Report

## Title
Blacklisted ERC-20 Recipient Permanently Freezes Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`finTransfer` in `OmniBridge.sol` delivers tokens directly to `payload.recipient` in a single atomic call with no fallback path. When the destination token (e.g., USDC, USDT) blacklists the recipient, every relay attempt reverts and rolls back the nonce flag, leaving it permanently unconsumed. Because the NEAR contract has already burned or locked the originating tokens in `init_transfer_internal` and exposes no public cancellation or refund entry point, the bridged funds are irrecoverably frozen.

## Finding Description
**EVM delivery path — `OmniBridge.sol` `finTransfer`:**

`completedTransfers[payload.destinationNonce] = true` is written at line 287, before any token movement. If the subsequent `safeTransfer` (line 351–354) reverts — as USDC's `_beforeTokenTransfer` hook unconditionally does for blacklisted addresses — the EVM runtime rolls back the entire transaction, including the nonce flag. The nonce is therefore never consumed, and every subsequent relay attempt fails identically. There is no fallback branch, no escrow, and no alternative recipient.

**NEAR source-side state is already committed — `init_transfer_internal`:**

Before the relayer ever touches the EVM side, `init_transfer_internal` calls `burn_tokens_if_needed` (line 1851) and `lock_tokens_if_needed` (lines 1853–1857) and then emits `InitTransferEvent` (line 1863). The token destruction is irreversible at this point.

**No public recovery path on NEAR:**

A full inspection of `near/omni-bridge/src/lib.rs` confirms that `remove_transfer_message` (line 2194) and `remove_transfer_message_without_refund` (line 2213) are both private (`fn`, not `pub fn`) and are never exposed as callable entry points. No `cancel_transfer`, `refund_transfer`, or equivalent public function exists. The only call site for `remove_transfer_message` is the internal `sign_transfer_callback` (line 657), which removes the pending transfer record after signing — but does not re-mint or unlock the already-burned tokens.

**Starknet identical structure:**

In `starknet/src/omni_bridge.cairo`, `_set_transfer_finalised` is called (line 250) before the `transfer` call (line 261), and `assert(success, 'ERR_TRANSFER_FAILED')` (line 262) reverts the whole transaction on failure, rolling back the nonce flag identically to the EVM case.

## Impact Explanation
Permanent freezing of bridged funds. Tokens burned or locked on NEAR can never be delivered to the EVM (or Starknet) recipient and cannot be reclaimed by the sender. This directly matches the allowed critical impact: *"permanent freezing of bridged funds across NEAR, EVM … flows."*

## Likelihood Explanation
USDC and USDT — both of which implement address blacklists — are primary bridging targets on every supported EVM chain (Ethereum, Arbitrum, Base, Polygon). Circle and Tether can blacklist an address at any time, including in the window between a user submitting `init_transfer` on NEAR and the relayer calling `finTransfer` on EVM. No privileged access is required: any ordinary user who sends to an address that becomes blacklisted (sanctions enforcement, exchange compliance, compromised wallet) triggers the freeze. The condition is externally imposed and outside the bridge's control.

## Recommendation
Replace the direct-push delivery in `finTransfer` with a pull pattern:

1. Instead of calling `safeTransfer(payload.recipient, payload.amount)` directly, credit the amount to a per-recipient claimable balance mapping inside the bridge contract and mark the nonce as consumed unconditionally.
2. Expose a separate `claimTokens(address token)` function that the recipient calls to pull their balance.
3. This isolates a blacklisted recipient: only their own `claimTokens` call fails; all other `finTransfer` calls succeed and consume the nonce normally.

For the NEAR side, add a DAO-gated `cancel_outbound_transfer(transfer_id)` entry point that re-mints (for deployed/bridged tokens) or unlocks (for native tokens) the original amount back to the sender when a cross-chain delivery is provably undeliverable.

## Proof of Concept
1. Alice holds 10,000 USDC on NEAR (bridged token). She calls `ft_transfer_call` targeting the NEAR bridge contract with recipient `0xBob` on Ethereum.
2. `init_transfer_internal` calls `burn_tokens_if_needed` (line 1851) — Alice's 10,000 USDC are burned on NEAR — then emits `InitTransferEvent` (line 1863).
3. Before the relayer acts, Circle blacklists `0xBob` (e.g., sanctions enforcement).
4. The relayer calls `finTransfer` on `OmniBridge.sol` with `payload.recipient = 0xBob`.
5. `completedTransfers[nonce] = true` is written (line 287), then `IERC20(USDC).safeTransfer(0xBob, 10000e6)` (line 351) reverts — USDC's blacklist hook rejects the transfer.
6. The EVM transaction reverts entirely; `completedTransfers[nonce]` is rolled back to `false`.
7. Every subsequent relay attempt reverts identically. The nonce is never consumed.
8. Alice's 10,000 USDC are permanently burned on NEAR. No public `cancel_transfer` or refund path exists (`remove_transfer_message` at line 2194 and `remove_transfer_message_without_refund` at line 2213 are both private). Funds are irrecoverably frozen.

**Minimal test plan:** Deploy a local fork with a mock ERC-20 that reverts `transfer` for a specific address. Call `initTransfer` on the NEAR localnet, observe token burn, then call `finTransfer` on the EVM fork targeting the blocked address. Assert the EVM transaction reverts on every attempt and that no NEAR-side recovery function exists.