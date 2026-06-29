Audit Report

## Title
Native ETH Delivery Revert in `finTransfer` Permanently Freezes Bridged Funds — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary
When a user bridges native ETH from NEAR to EVM and specifies a contract recipient that cannot accept plain ETH transfers, every call to `finTransfer` reverts via `FailedToSendEther`. Because Solidity reverts roll back all state changes, the nonce-consumed marking is also undone, leaving the transfer permanently retryable but permanently failing. The user's NEAR-side tokens (locked or burned at initiation) have no user-callable recovery path, resulting in permanent fund freeze.

## Finding Description
In `OmniBridge.finTransfer` (lines 283–322), the destination nonce is marked consumed at line 287 before any token delivery occurs:

```solidity
completedTransfers[payload.destinationNonce] = true;   // L287
```

For native ETH transfers (`payload.tokenAddress == address(0)`), delivery is attempted at lines 317–322:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
```

`revert FailedToSendEther()` rolls back the entire transaction, including the `completedTransfers` write at L287. The nonce is therefore never permanently consumed. A relayer can retry indefinitely, but every attempt produces the same revert when the recipient is a contract with no `receive`/`fallback` or one that explicitly reverts on ETH receipt.

On the NEAR side, `init_transfer_internal` locks or burns the user's tokens (lib.rs L1850–1857) before the cross-chain message is emitted. The `remove_transfer_message` function is only invoked through internal callbacks (e.g., storage-deposit failure paths), not through any public, user-callable entry point. There is no cancel or refund function that the original sender can invoke to reclaim tokens from a `TransferMessage` whose EVM finalization is permanently blocked.

## Impact Explanation
This constitutes **permanent freezing of bridged funds**, which is explicitly listed as a Critical impact in the allowed scope. The user's NEAR tokens are irrecoverably locked or burned: the EVM leg can never succeed for the given recipient, the NEAR leg has no user-accessible refund path, and the relayer's ETH is returned on each revert so no external party is incentivized to resolve the situation. The frozen amount equals the full bridged value.

## Likelihood Explanation
Low-to-medium. No privileged access is required; any bridge user can trigger this by specifying a contract address as the EVM recipient. Realistic triggering conditions include: bridging ETH to a Gnosis Safe or multisig that lacks a `receive` function; bridging to a contract that was upgraded after the user initiated the transfer and whose `receive` function was removed; or a user inadvertently pasting a token contract address as the recipient. All of these are plausible, non-adversarial scenarios that require no attacker — the user harms only themselves.

## Recommendation
Replace the hard revert on ETH delivery failure with a pull-payment (escrow) pattern so the nonce is consumed and the ETH is held safely for later claim:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) {
        pendingWithdrawals[payload.recipient] += payload.amount;
        emit EthDeliveryFailed(payload.recipient, payload.amount, payload.destinationNonce);
    }
}
```

This ensures the nonce is permanently consumed (preventing replay), the ETH remains in the contract, and the recipient or an admin-assisted path can later withdraw it. Alternatively, add a NEAR-side user-callable cancel entry point that allows the original sender to reclaim tokens when EVM finalization is provably impossible (e.g., after a timeout or explicit failure proof).

## Proof of Concept
1. User on NEAR calls `ft_transfer_call` → `init_transfer_internal` → NEAR tokens locked/burned, `TransferMessage` stored (lib.rs L1850–1857).
2. User specifies as EVM recipient a contract `C` with no `receive` function (e.g., a plain ERC-20 token contract address).
3. Relayer calls `finTransfer` on EVM with `msg.value = payload.amount`.
4. L287: `completedTransfers[nonce] = true` (state written).
5. L319–321: `C.call{value: amount}("")` returns `success = false`.
6. L322: `revert FailedToSendEther()` — entire transaction rolls back, including L287.
7. Relayer retries; every attempt reverts identically. Relayer's ETH is returned each time.
8. User's NEAR tokens remain locked/burned. No public NEAR entry point allows the user to cancel or reclaim. Funds are permanently frozen.

To reproduce locally: deploy a contract with no `receive` function on an EVM testnet fork, initiate a NEAR→EVM ETH bridge transfer targeting that contract, and call `finTransfer` — observe the revert and confirm `completedTransfers[nonce]` remains `false` after each attempt.