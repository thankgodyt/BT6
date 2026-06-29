Audit Report

## Title
Blacklisted ERC-20 Recipient Permanently Freezes Bridged Funds in `finTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`finTransfer` in `OmniBridge.sol` marks the destination nonce as used at line 287 and then attempts the token transfer later in the same atomic transaction. Because Solidity reverts roll back all state changes, a failed `safeTransfer` (e.g., USDC/USDT blacklist hit) also rolls back the nonce marking, leaving the nonce permanently unconsumed. With no on-chain redirect or escrow fallback, and with the corresponding tokens already burned or locked on NEAR during `init_transfer_internal`, the bridged funds become permanently undeliverable.

## Finding Description

`finTransfer` executes the following sequence atomically:

1. **Nonce guard** (L283–285): reverts if `completedTransfers[payload.destinationNonce]` is already `true`.
2. **Nonce mark** (L287): sets `completedTransfers[payload.destinationNonce] = true`.
3. **Signature verification** (L311–313): recovers signer via `ECDSA.recover`; reverts on mismatch.
4. **Token delivery** (L317–354): for native ETH uses a low-level call that reverts on failure; for plain ERC-20 (the `else` branch at L350–354) calls `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)`.

Because steps 2 and 4 share the same transaction, any revert in step 4 rolls back the write in step 2. The nonce is therefore never durably consumed. The signed MPC payload remains valid and replayable, but every replay against a blacklisted recipient will revert identically.

On the NEAR side, `init_transfer_internal` (L1851) calls `burn_tokens_if_needed` and (L1853–1857) `lock_tokens_if_needed` before emitting `InitTransferEvent`. There is no user-callable cancel or refund path in the NEAR contract that would allow recovery of those burned/locked tokens once the outbound transfer message is stored. The EVM contract likewise contains no escrow, claimable-balance, or admin-redirect mechanism for failed deliveries.

## Impact Explanation

This is a **Critical** impact matching the allowed scope: *permanent freezing of bridged funds*. A user who bridges USDC (or any token with a transfer blacklist) from NEAR to an EVM address that is blacklisted at delivery time will have their tokens irreversibly burned on NEAR while the EVM delivery permanently fails. The signed payload is valid but undeliverable; the nonce is never consumed; and no on-chain path exists to recover or redirect the funds.

## Likelihood Explanation

USDC and USDT both maintain on-chain blacklists and are explicitly supported bridge tokens. A recipient address can become blacklisted after `init_transfer` is called but before the relayer calls `finTransfer` (a race condition requiring no privileged access). This is reachable by any bridge user without any special role, and the scenario has real-world precedent (regulatory blacklisting of addresses). The exploit requires no attacker — it is triggered by normal bridge usage combined with an external blacklisting event.

## Recommendation

Separate nonce finalization from token delivery:

1. **Two-step pull delivery**: After verifying the MPC signature and marking the nonce used, credit the amount to an internal `claimable[recipient][token]` mapping instead of pushing tokens immediately. Add a `claimTransfer(nonce)` function that lets the recipient (or an admin on their behalf) pull the tokens. The nonce is consumed regardless of whether the immediate push succeeds.

2. **Try/catch with escrow on failure**: Wrap the `safeTransfer` in a low-level call; on failure, escrow the tokens under the recipient's address in the bridge contract and emit an event, allowing an admin or the recipient to redirect the escrowed funds later.

3. **NEAR-side cancel path**: Add a `cancel_transfer` function on NEAR that, given proof that the EVM nonce was never finalized, refunds the burned/locked tokens to the original sender.

## Proof of Concept

1. Alice holds NEAR-side USDC and calls `ft_transfer_call` to bridge 10,000 USDC to `0xAlice` on Ethereum. `init_transfer_internal` burns the tokens on NEAR and emits `InitTransferEvent`.
2. Between step 1 and step 3, Circle blacklists `0xAlice` on the USDC contract.
3. The relayer calls `finTransfer` on `OmniBridge.sol` with the valid MPC-signed payload targeting `0xAlice`.
4. Execution reaches L351–354: `IERC20(usdc).safeTransfer(0xAlice, 10000e6)` reverts because `0xAlice` is blacklisted.
5. The entire transaction reverts; the write at L287 (`completedTransfers[nonce] = true`) is rolled back.
6. Every subsequent call to `finTransfer` with the same payload reverts identically.
7. Alice's 10,000 USDC are permanently burned on NEAR and undeliverable on Ethereum.

A local integration test can reproduce this by deploying a mock USDC with a blacklist, calling `finTransfer` after blacklisting the recipient, and asserting that `completedTransfers[nonce]` remains `false` after the revert while the bridge holds the tokens with no withdrawal path.