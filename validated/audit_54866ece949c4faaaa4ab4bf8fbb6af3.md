Audit Report

## Title
`finTransfer` Push-Transfer to Blacklisted Recipient Permanently Freezes Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`OmniBridge.sol::finTransfer` uses a push-transfer pattern that calls `IERC20.safeTransfer` directly to `payload.recipient`. If the recipient is blacklisted by a transfer-restricted token (e.g., USDC, USDT), the `safeTransfer` reverts the entire transaction on every attempt. Because no pull-based claim mechanism exists on EVM and no cancel/refund path exists on NEAR for outbound transfers, the user's already-burned or locked tokens are permanently frozen.

## Finding Description

In `finTransfer`, the nonce guard and nonce assignment occur at lines 283–287, followed by signature verification, and then token delivery at lines 350–355. For non-bridge, non-custom-minter ERC20 tokens (the path taken by USDC, USDT, and other externally-held assets), the final `else` branch executes:

```solidity
// OmniBridge.sol L350-355
} else {
    IERC20(payload.tokenAddress).safeTransfer(
        payload.recipient,
        payload.amount
    );
}
```

When `payload.recipient` is on the token's blacklist, `safeTransfer` reverts. Because Solidity reverts unwind all state changes, `completedTransfers[payload.destinationNonce]` is also rolled back — the nonce is never consumed. However, every subsequent retry by any relayer produces the identical revert, since the blacklist condition is external and persistent.

There is no `claim()` or pull-withdrawal function anywhere in `OmniBridge.sol`. On the NEAR side, `pending_transfers` stores the outbound `TransferMessage` indefinitely; no `cancel`, `refund`, or `rollback` function exists for outbound (NEAR → EVM) transfers. The MPC-signed payload encodes `recipient` as a fixed field — neither the relayer nor the user can substitute a different destination address without a new MPC signature over a different payload, which the NEAR contract will not produce for an already-pending transfer.

## Impact Explanation

This concretely satisfies the Critical impact criterion: **permanent freezing of bridged funds**. Tokens locked or burned on NEAR during `initTransfer` are irrecoverable — they cannot be delivered on EVM (every `finTransfer` reverts) and cannot be reclaimed on NEAR (no cancel path). The bridge's escrow accounting is permanently mis-stated: NEAR records the tokens as transferred out, EVM never records them as received.

## Likelihood Explanation

USDC and USDT are among the most frequently bridged assets. Circle and Tether regularly blacklist addresses under OFAC sanctions compliance. A user may be blacklisted in the window between `initTransfer` on NEAR (tokens burned/locked) and `finTransfer` on EVM (relayer latency + MPC signing time). No privileged access is required; the condition is triggered by an external compliance action entirely outside the user's or protocol's control. The scenario is realistic and repeatable for any blacklisted address attempting to bridge USDC or USDT from NEAR to EVM.

## Recommendation

Replace the push-transfer pattern with a pull-based (claim) pattern for the non-bridge-token ERC20 path:

1. Instead of calling `safeTransfer` inside `finTransfer`, record the claimable balance: `claimable[payload.recipient][payload.tokenAddress] += payload.amount`.
2. Consume the nonce and emit the event unconditionally, decoupling finalisation from delivery.
3. Add a `claim(address tokenAddress, address recipient)` function allowing the recipient (or an authorized substitute) to withdraw their balance.
4. Optionally, add a `redirectClaim(address tokenAddress, address newRecipient)` callable only by the original recipient, to handle permanent blacklist situations.

## Proof of Concept

1. Alice holds USDC on NEAR and calls `initTransfer` targeting her EVM address `0xAlice`. USDC is locked in the NEAR bridge contract; a `TransferMessage` is stored in `pending_transfers`.
2. Before the relayer finalises, Circle blacklists `0xAlice`.
3. The relayer calls `finTransfer` on `OmniBridge.sol` with the MPC-signed payload for `0xAlice`.
4. Execution reaches line 351: `IERC20(USDC).safeTransfer(0xAlice, amount)` — USDC's internal `_transfer` reverts because `0xAlice` is blacklisted.
5. The entire transaction reverts; `completedTransfers[nonce]` is rolled back to `false`.
6. Every subsequent relayer retry produces the same revert.
7. No `claim()` function exists in `OmniBridge.sol`; no `cancel` or `refund` function exists in `near/omni-bridge/src/lib.rs` for outbound transfers.
8. Alice's USDC is permanently frozen: burned/locked on NEAR, undeliverable on EVM.

**Minimal local test plan:** Deploy `OmniBridge` against a mock USDC that reverts `transfer` for a specific address. Call `finTransfer` with that address as `payload.recipient`. Assert the transaction reverts and `completedTransfers[nonce]` remains `false`. Confirm no alternative function exists to recover the funds.