Audit Report

## Title
Native ETH Delivery Failure to ETH-Rejecting Recipient Permanently Freezes Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

In `OmniBridge.finTransfer`, when finalizing a native ETH bridge transfer (`payload.tokenAddress == address(0)`), ETH is delivered via a bare low-level call to `payload.recipient`. If the recipient is a contract that reverts on ETH receipt, the entire `finTransfer` transaction reverts — including the `completedTransfers` nonce write — leaving the nonce unconsumed and the transfer permanently unfinalizeable. Because the signed payload is immutable and no fallback delivery mechanism exists, the user's funds locked on NEAR are permanently frozen.

## Finding Description

In `finTransfer`, the nonce is marked consumed at line 287 before the ETH delivery attempt:

```solidity
completedTransfers[payload.destinationNonce] = true;  // L287
```

Then at lines 317–322, native ETH is delivered:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

If `payload.recipient` is a contract with no `receive`/`fallback`, or one that explicitly reverts, `success` is `false` and `revert FailedToSendEther()` fires. This reverts the entire transaction, including the `completedTransfers[payload.destinationNonce] = true` write at line 287. The nonce is therefore never consumed.

The `payload.recipient` is encoded in the MPC-signed `TransferMessagePayload` and is immutable post-signing. There is no WETH fallback, no admin rescue path, and no mechanism to redirect delivery. Every relay attempt will fail identically and indefinitely.

## Impact Explanation

The user's native ETH equivalent is locked or burned on the NEAR source chain at `initTransfer` time. On the EVM destination, `finTransfer` can never succeed because the recipient always rejects ETH. This constitutes **permanent freezing of bridged funds**, which is an explicitly listed Critical impact: *"Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM..."*

## Likelihood Explanation

Any bridge user can trigger this by specifying a contract address as the EVM recipient when initiating a native ETH transfer on NEAR. This occurs accidentally when users specify multisigs, DAO treasuries, or smart contract wallets lacking a `receive` function — a common real-world scenario. It can also be triggered intentionally by deploying an ETH-rejecting contract and using its address as the recipient. No special privileges, admin access, or external dependencies are required.

## Recommendation

Replace the bare ETH call with a try-WETH fallback pattern:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) {
    IWETH(weth).deposit{value: payload.amount}();
    IERC20(weth).safeTransfer(payload.recipient, payload.amount);
}
```

Alternatively, detect contract recipients via `payload.recipient.code.length > 0` and always deliver as WETH to contracts. This is a well-established pattern in production bridges and AMMs.

## Proof of Concept

1. Deploy `EthRejecter` on the EVM destination chain:
   ```solidity
   contract EthRejecter {
       receive() external payable { revert("NO ETH"); }
   }
   ```
2. On NEAR, call `initTransfer` for a native ETH bridge transfer specifying `address(ethRejecter)` as the EVM recipient. NEAR locks/burns the user's funds and produces a signed `TransferMessagePayload`.
3. A relayer calls `OmniBridge.finTransfer(signatureData, payload)`.
4. Execution reaches line 287: `completedTransfers[payload.destinationNonce] = true` — state written.
5. Execution reaches line 319: `payload.recipient.call{value: payload.amount}("")` — `EthRejecter.receive()` reverts, `success = false`.
6. Line 322: `revert FailedToSendEther()` — entire transaction reverts, undoing the line 287 write.
7. The nonce is unconsumed. Every subsequent relay attempt fails identically. The user's funds are permanently frozen with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L5-14)
```text
    struct TransferMessagePayload {
        uint64 destinationNonce;
        uint8 originChain;
        uint64 originNonce;
        address tokenAddress;
        uint128 amount;
        address recipient;
        string feeRecipient;
        bytes message;
    }
```
