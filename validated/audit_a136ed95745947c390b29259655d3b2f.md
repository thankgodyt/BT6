Audit Report

## Title
Blacklisted EVM Recipient Causes Permanent Freezing of Bridged Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary
When a NEAR → EVM bridge transfer is in flight and the EVM recipient address is blacklisted by the token contract (e.g., USDC, USDT), every `finTransfer` call on the EVM bridge reverts because `safeTransfer` to a blacklisted address is rejected by the token. Because the recipient is cryptographically bound into the MPC-signed Borsh payload and there is no cancel or refund path on the NEAR side, the tokens burned or locked during `init_transfer` are permanently irrecoverable.

## Finding Description

**EVM path — `finTransfer` always reverts for a blacklisted recipient**

`finTransfer` in `OmniBridge.sol` sets the nonce consumed flag before attempting the token delivery:

```solidity
completedTransfers[payload.destinationNonce] = true;   // L287
```

It then attempts to deliver tokens to `payload.recipient` (L351–354 for the `safeTransfer` branch). If `payload.recipient` is on USDC's `_blacklisted` mapping, `safeTransfer` reverts, rolling back the entire transaction — including the nonce flag. The nonce is therefore never consumed, and the relayer can retry indefinitely, but every retry produces the same revert because `payload.recipient` is hardcoded in the Borsh-encoded message that is verified against the MPC-derived address (L289–313). Any change to `payload.recipient` invalidates the ECDSA signature.

**NEAR path — no cancel or refund mechanism**

On the NEAR side, `init_transfer_internal` burns or locks the user's tokens and stores the transfer in `pending_transfers` (L1850–1857). The only path that removes a `pending_transfers` entry after this point is `claim_fee_callback`, which requires proof of a successful EVM `FinTransfer` event (L1094). Since `finTransfer` on EVM can never succeed for a blacklisted recipient, `claim_fee_callback` can never be triggered, and the entry — along with the burned/locked tokens — remains permanently frozen.

**Secondary NEAR inbound path — `ft_transfer` failure silently ignored**

In `process_fin_transfer_to_near`, `send_tokens` uses plain `ft_transfer` (not `ft_transfer_call`) when `msg` is empty (L2102–2106). The `is_ft_transfer_call` flag passed to `fin_transfer_send_tokens_callback` is `!msg.is_empty()` (L1973), so it is `false` for the plain-transfer path. `is_refund_required(false)` unconditionally returns `false` (L1800–1803) regardless of the promise result. If `ft_transfer` fails (e.g., a NEAR-native token with a blacklist rejects the recipient), the callback takes the success branch, logs `FinTransferEvent`, and the tokens remain stuck in the bridge contract with no recovery path.

## Impact Explanation

The primary EVM-side path results in complete, irrecoverable loss of the user's bridged assets: tokens burned or locked on NEAR cannot be recovered because the EVM finalization step can never succeed and no cancel/refund function exists. This is a concrete instance of **permanent freezing of bridged funds**, which is an explicitly listed Critical impact for the NEAR Omni Bridge program. The secondary NEAR inbound path produces the same outcome for NEAR-native tokens with transfer restrictions.

## Likelihood Explanation

USDC and USDT — two of the most commonly bridged assets — maintain on-chain blacklists actively enforced by Circle and Tether. A user whose EVM address is blacklisted after initiating a bridge transfer, or who specifies a recipient that is subsequently blacklisted during the multi-step bridge process (init → MPC signing → relayer submission), will have their funds permanently frozen. The probability per individual transfer is low but non-zero and has real-world precedent (Circle has blacklisted thousands of addresses). No attacker capability is required; the trigger is an external regulatory action against the recipient address.

## Recommendation

**EVM side (`OmniBridge.sol`):** Implement a pull-payment (escrow) pattern: instead of pushing tokens directly to `payload.recipient` in `finTransfer`, credit the amount to an internal `claimable[recipient][token]` mapping and emit an event. The recipient (or, if blacklisted, the original sender proven via the signed payload) can then call a separate `claim` function to withdraw to any non-blacklisted address. Alternatively, add a `recipientOverride` parameter to `finTransfer` that is only accepted when accompanied by a valid MPC signature over the override address, allowing the original sender to redirect funds.

**NEAR side (`lib.rs`):** In `fin_transfer_send_tokens_callback`, check the promise result unconditionally, not only when `is_ft_transfer_call` is `true`. If the promise result is `Failed`, execute the same revert path (burn tokens if needed, revert lock actions, remove the finalization record) regardless of whether the transfer used `ft_transfer` or `ft_transfer_call`. Additionally, implement a standalone `cancel_transfer` function that allows the original sender to cancel a pending transfer and receive a refund when the transfer has been pending beyond a configurable timeout and no EVM finalization proof has been submitted.

## Proof of Concept

**EVM path (step-by-step):**
1. Alice holds 10,000 USDC on NEAR and calls `ft_transfer_call` to the bridge with an `InitTransfer` message specifying `recipient = 0xAlice` on Ethereum.
2. `init_transfer_internal` burns Alice's USDC and stores the `TransferMessage` in `pending_transfers` (L1850–1857).
3. The MPC network signs the Borsh-encoded payload binding `recipient = 0xAlice`.
4. Circle blacklists `0xAlice` (regulatory action).
5. Relayer calls `finTransfer(signature, payload)` on EVM — `IERC20(usdc).safeTransfer(0xAlice, 10000e6)` reverts because USDC's `transfer` function checks `_blacklisted[to]`.
6. The entire EVM transaction reverts; `completedTransfers[nonce]` is rolled back to `false`.
7. Relayer retries — same result indefinitely. Any attempt to modify `payload.recipient` invalidates the ECDSA signature verified at L311–313.
8. Alice's 10,000 USDC is permanently locked in the NEAR bridge contract. `claim_fee_callback` can never be triggered because it requires proof of a successful EVM `FinTransfer` event (L1094). No cancel function exists.

**NEAR inbound path (step-by-step):**
1. A relayer calls `fin_transfer` for a NEAR-native token transfer with empty `msg`.
2. `process_fin_transfer_to_near` calls `send_tokens` → `ft_transfer(recipient, amount, None)` (L2103–2106).
3. The token contract rejects the transfer (e.g., blacklisted recipient), returning a `Failed` promise result.
4. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
5. `is_refund_required(false)` returns `false` (L1800–1803) without inspecting the promise result.
6. The callback takes the success branch, logs `FinTransferEvent`, and marks the transfer finalized.
7. Tokens remain in the bridge contract; the transfer ID is recorded as finalized, preventing any retry.