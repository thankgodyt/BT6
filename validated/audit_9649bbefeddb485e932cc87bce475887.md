Audit Report

## Title
Push-Payment ETH Delivery in `finTransfer` Permanently Freezes Bridged Funds When Recipient Reverts — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary
`OmniBridge.finTransfer` delivers native ETH via a direct push-call to `payload.recipient`. Because the recipient address is cryptographically bound in the MPC-signed payload and cannot be altered, any recipient contract that lacks a `receive()` function or reverts on ETH receipt will cause every finalization attempt to revert permanently. The corresponding NEAR-side tokens are already burned or locked before the EVM leg executes, with no protocol-level recovery path, resulting in permanent freezing of bridged funds.

## Finding Description
In `finTransfer`, the nonce is marked used at line 287 before the transfer branch executes:

```solidity
completedTransfers[payload.destinationNonce] = true;  // line 287
```

For native ETH (`payload.tokenAddress == address(0)`), the contract pushes ETH directly to the recipient at lines 319–322:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
```

If the recipient reverts, `revert FailedToSendEther()` rolls back the entire transaction, including the nonce write at line 287. The nonce is therefore never durably consumed, so the transfer can be retried — but every retry produces the same revert because the recipient is immutably bound in the Borsh-encoded payload verified at lines 311–313:

```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

The `payload.recipient` field (encoded at line 298) is part of the signed hash; no field can be changed without invalidating the MPC signature. On the NEAR side, `init_transfer_internal` (lines 1850–1863 of `near/omni-bridge/src/lib.rs`) burns deployed tokens or locks native tokens and emits `InitTransferEvent` before any EVM interaction occurs. This NEAR-side commitment is irreversible: there is no un-burn or un-lock path if the EVM leg fails permanently. A grep across all EVM Solidity files confirms no `pendingWithdrawals`, `claimETH`, `rescue`, or pull-payment mechanism exists in `OmniBridge.sol`. The only theoretical recovery is a UUPS upgrade (`_authorizeUpgrade`, line 594–596), which is an out-of-band emergency measure, not a protocol safeguard.

The same root cause applies to the ERC-1155 path (`safeTransferFrom` invokes `onERC1155Received`, which can revert) and to ERC-20 tokens with transfer blacklists (e.g., USDC `safeTransfer` reverts for blacklisted addresses), as shown in lines 323–355.

## Impact Explanation
A user whose NEAR → EVM transfer targets a contract recipient that cannot accept ETH will have their NEAR-side tokens permanently burned with zero recourse. The ETH is never delivered, the nonce is never consumed, and no alternative delivery path exists. This constitutes **permanent freezing of bridged funds**, which falls squarely within the Critical impact scope: *"Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM..."*

## Likelihood Explanation
The scenario is realistic under two independent conditions:

1. **Contract recipient without ETH acceptance** — Users routinely bridge to multisig wallets, DeFi vaults, or other contracts. Many such contracts lack a `receive()` function. Any user who specifies such an address as the EVM recipient will permanently lose their NEAR tokens. No privileged access is required; the user simply initiates a standard NEAR → EVM transfer.

2. **ERC-20 blacklist race** — For USDC or similar tokens, Circle can blacklist an address between the moment the NEAR-side burn is committed and the moment the relayer calls `finTransfer` on EVM. This is an externally triggerable condition that permanently freezes the transfer without any action by the user.

Both conditions are reachable by any bridge user without privileged access.

## Recommendation
Replace the push-payment pattern with a pull-payment (claimable balance) pattern for ETH delivery:

```solidity
// Instead of pushing ETH:
pendingWithdrawals[payload.recipient] += payload.amount;
emit ETHPending(payload.recipient, payload.amount);

function claimETH() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "FailedToSendEther");
}
```

For ERC-20 tokens with blacklists, consider a similar claimable-balance mapping so that a blacklisted recipient does not permanently block finalization. Additionally, consider an admin-accessible rescue path that can redirect a stuck transfer to an alternative address after a timeout, analogous to the NEAR contract's existing `migrate_deployed_token` pattern.

## Proof of Concept
**Setup:** Deploy a malicious contract `NoReceive` on an EVM testnet:

```solidity
contract NoReceive {
    // No receive() or fallback() — ETH transfers revert
}
```

**Attack flow:**

1. On NEAR, call `ft_on_transfer` (or equivalent) to initiate a transfer of wrapped ETH to `NoReceive`'s address. `init_transfer_internal` (lines 1850–1863, `near/omni-bridge/src/lib.rs`) burns the wrapped ETH and emits `InitTransferEvent`. The NEAR-side commitment is now irreversible.

2. The relayer calls `sign_transfer` on NEAR. The MPC network signs a `TransferMessagePayload` with `recipient = address(NoReceive)` and `tokenAddress = address(0)`.

3. The relayer calls `OmniBridge.finTransfer(signature, payload)` on EVM with `msg.value = payload.amount`.

4. Execution reaches line 319. `NoReceive` has no `receive()`, so the low-level call returns `success = false`. The function reverts with `FailedToSendEther` (line 322). The nonce write at line 287 is rolled back.

5. Every subsequent retry produces the same revert. The nonce is never durably consumed.

6. The user's NEAR-side wrapped ETH is permanently burned. The ETH remains with the relayer (returned on revert). The user has no recovery path.