Looking at the actual code to validate each claim in the report.

Audit Report

## Title
Push-Payment ETH Delivery in `finTransfer` Permanently Freezes Bridged Funds When Recipient Reverts — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary

`OmniBridge.finTransfer` delivers native ETH via a direct push-call to `payload.recipient`. If the recipient is a contract that cannot accept ETH, the call returns `success = false` and the function reverts with `FailedToSendEther`, rolling back the nonce marking. Because the NEAR-side token burn in `init_transfer_internal` is already committed and irreversible, the user's wrapped ETH is permanently destroyed with no EVM delivery and no recovery path.

## Finding Description

In `finTransfer`, the nonce is marked consumed at line 287 before any transfer attempt:

```solidity
completedTransfers[payload.destinationNonce] = true;
```

For native ETH (`payload.tokenAddress == address(0)`), the contract then pushes ETH directly to the recipient at lines 317–322:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
```

If the recipient has no `receive()` function or a reverting `receive()`, `success` is `false` and the function reverts. Because Solidity reverts roll back all state changes in the transaction, the `completedTransfers` assignment at line 287 is also rolled back — the nonce is never durably consumed. Every subsequent retry by the relayer produces the same revert.

The recipient address is Borsh-encoded into the MPC-signed payload at line 298 (`Borsh.encodeAddress(payload.recipient)`) and the signature is verified against `nearBridgeDerivedAddress` at lines 311–313. No field in the payload — including `recipient` — can be altered without invalidating the signature, so there is no way to redirect the transfer to a different address.

On the NEAR side, `init_transfer_internal` calls `burn_tokens_if_needed` at line 1851 and emits `InitTransferEvent` at line 1863 before any EVM interaction. The burn is a fire-and-forget detached promise (`ext_token::ext(token).burn(amount).detach()`), making it irreversible once the NEAR transaction finalizes.

No pull-payment fallback, claimable-balance mapping, or admin rescue function exists in `OmniBridge.sol`. The only theoretical recovery path is a UUPS contract upgrade via `_authorizeUpgrade` at lines 594–596, which is an out-of-band emergency measure requiring admin key action, not a protocol-level safeguard.

The same root cause applies to the ERC-1155 path (`safeTransferFrom` invokes `onERC1155Received` on the recipient, which can revert) and to ERC-20 tokens with transfer blacklists such as USDC (`safeTransfer` reverts for blacklisted addresses at lines 350–354).

## Impact Explanation

A user whose NEAR → EVM transfer targets a contract recipient that cannot accept ETH will have their NEAR-side wrapped ETH permanently burned with zero recourse. The ETH is never delivered, the nonce is never consumed, and no alternative delivery path exists. This constitutes **permanent freezing of bridged funds**, which falls squarely within the Critical impact scope: "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."

## Likelihood Explanation

The scenario is realistic under two independent conditions:

1. **Contract recipient without ETH acceptance** — Users routinely bridge to multisig wallets, DeFi vaults, or other contracts. Many such contracts lack a `receive()` function. Any user who specifies such an address as the EVM recipient will permanently lose their NEAR tokens. No privileged access is required; the user triggers this through the normal `ft_transfer_call` → `sign_transfer` → relayer `finTransfer` flow.

2. **ERC-20 blacklist race** — For USDC or similar tokens, Circle can blacklist an address between the moment the NEAR-side burn is committed and the moment the relayer calls `finTransfer` on EVM. This is an externally triggerable condition that permanently freezes the transfer.

Both conditions are reachable by any bridge user without any privileged access.

## Recommendation

Replace the push-payment pattern with a pull-payment (claimable balance) pattern for ETH delivery:

```solidity
// Instead of pushing ETH:
pendingWithdrawals[payload.recipient] += payload.amount;
emit PendingWithdrawal(payload.recipient, payload.amount);

function claimETH() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "NothingToClaim");
    pendingWithdrawals[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "FailedToSendEther");
}
```

This ensures the nonce is durably consumed and the `FinTransfer` event is emitted regardless of whether the recipient can accept ETH at finalization time. For ERC-20 tokens with blacklists, consider a similar claimable-balance mapping. Additionally, consider an admin-accessible rescue path that can redirect a stuck transfer to an alternative address after a timeout.

## Proof of Concept

**Setup:** Deploy a contract `NoReceive` on a local EVM fork:

```solidity
contract NoReceive {
    // No receive() or fallback() — ETH transfers revert
}
```

**Attack flow:**

1. On NEAR, call `ft_transfer_call` to initiate a transfer of wrapped ETH to `NoReceive`'s address. `init_transfer_internal` calls `burn_tokens_if_needed` (line 1851) and emits `InitTransferEvent` (line 1863). The NEAR-side burn is committed and irreversible.

2. The relayer calls `sign_transfer` on NEAR. The MPC network signs a `TransferMessagePayload` with `recipient = address(NoReceive)` and `tokenAddress = address(0)`.

3. The relayer calls `OmniBridge.finTransfer(signature, payload)` on EVM with `msg.value = payload.amount`.

4. Execution reaches line 287: `completedTransfers[payload.destinationNonce] = true`.

5. Execution reaches line 319: `NoReceive` has no `receive()`, so the low-level call returns `success = false`. The function reverts with `FailedToSendEther`, rolling back the line 287 state change.

6. The nonce is not durably consumed. Every subsequent retry produces the same revert.

7. The user's NEAR-side wrapped ETH is permanently burned. The ETH remains with the relayer (returned on revert). The user has no recovery path.

**Verification:** Assert that after the revert, `completedTransfers[payload.destinationNonce]` is `false`, confirming the nonce was rolled back and the transfer is permanently stuck.