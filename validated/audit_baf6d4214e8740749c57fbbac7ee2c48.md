Audit Report

## Title
`finTransferExtension` Forwards Full `msg.value` After Native ETH Already Sent to Recipient, Permanently Freezing Native ETH Bridge Transfers - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary

`OmniBridge.finTransfer` sends `payload.amount` of ETH to the recipient before calling `finTransferExtension`. `OmniBridgeWormhole.finTransferExtension` then attempts to forward the original `msg.value` to Wormhole's `publishMessage`, but the contract's balance is only `msg.value - payload.amount` at that point. The call reverts unconditionally for every native ETH (`tokenAddress == address(0)`) finalization on Wormhole-connected chains, permanently freezing the bridged funds on the source chain.

## Finding Description

In `OmniBridge.finTransfer` (lines 317–322 and 357), when `payload.tokenAddress == address(0)`, the contract immediately forwards `payload.amount` wei to the recipient:

```solidity
// OmniBridge.sol L317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

After this, `finTransferExtension(payload)` is called: [2](#0-1) 

`OmniBridgeWormhole.finTransferExtension` then attempts to send the full original `msg.value` to Wormhole:

```solidity
// OmniBridgeWormhole.sol L109-113
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
``` [3](#0-2) 

In Solidity, `msg.value` always reflects the original call value and does not decrease when ETH is sent out. However, the contract's actual ETH balance is now only `msg.value - payload.amount`. Attempting to forward `msg.value` when only `wormhole.messageFee()` remains causes the EVM to revert with an insufficient-balance error. The entire transaction reverts, so `completedTransfers[payload.destinationNonce]` is never set, and the relayer retries indefinitely — always failing identically.

The asymmetry with `initTransfer` is clear: it explicitly computes `extensionValue = msg.value - amount - nativeFee` and passes it as a parameter: [4](#0-3) 

`initTransferExtension` in `OmniBridgeWormhole` correctly uses that pre-computed `value` parameter: [5](#0-4) 

`finTransferExtension` has no equivalent accounting step. [6](#0-5) 

## Impact Explanation

This matches the critical impact class: **permanent freezing of bridged funds**. When a user bridges native ETH from NEAR to any Wormhole-connected chain (BNB Chain, Arbitrum, Base, Polygon), the relayer must call `finTransfer{value: payload.amount + wormhole.messageFee()}`. After the ETH is forwarded to the recipient, only `wormhole.messageFee()` remains in the contract. The `publishMessage` call reverts, rolling back the entire transaction. The source-chain lock is permanent; the destination-chain release can never succeed. Every native ETH bridge transfer to a Wormhole-connected chain is permanently broken.

## Likelihood Explanation

No special attacker capability is required. Any ordinary user initiating a native ETH bridge transfer from NEAR to a Wormhole-connected chain triggers this path. The relayer's `finTransfer` call reverts unconditionally and repeatably. The bug is hit by normal bridge usage with no preconditions beyond `tokenAddress == address(0)` and `payload.amount > 0`.

## Recommendation

Pass the remaining ETH balance as an explicit parameter to `finTransferExtension`, mirroring the pattern already used in `initTransferExtension`:

```solidity
// OmniBridge.sol - finTransfer
uint256 remainingValue = msg.value;
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
    remainingValue = msg.value - payload.amount;
}
...
finTransferExtension(payload, remainingValue);
```

Update `OmniBridgeWormhole.finTransferExtension` to accept and use `remainingValue` instead of `msg.value`, consistent with how `initTransferExtension` already handles the `value` parameter. [7](#0-6) 

## Proof of Concept

1. User bridges 1 ETH from NEAR → Arbitrum (a Wormhole-connected chain). Source side records the lock.
2. Relayer calls `OmniBridgeWormhole.finTransfer{value: 1 ETH + wormhole_fee}(sig, payload)` where `payload.tokenAddress = address(0)`, `payload.amount = 1 ETH`.
3. `finTransfer` executes `payload.recipient.call{value: 1 ETH}("")` — succeeds; contract balance is now `wormhole_fee`.
4. `finTransferExtension` executes `_wormhole.publishMessage{value: msg.value}(...)` where `msg.value = 1 ETH + wormhole_fee` — **reverts** because the contract only holds `wormhole_fee`.
5. The entire transaction reverts. `completedTransfers` is not updated. The relayer retries and fails identically every time. The 1 ETH is permanently frozen on NEAR.

A local Foundry test can reproduce this by deploying a mock `IWormhole` that checks `msg.value == messageFee()` and asserting that `finTransfer` reverts when `tokenAddress == address(0)` and `amount > 0`.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L357-357)
```text
        finTransferExtension(payload);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L391-391)
```text
            extensionValue = msg.value - amount - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L96-116)
```text
    function finTransferExtension(
        BridgeTypes.TransferMessagePayload memory payload
    ) internal override {
        bytes memory messagePayload = bytes.concat(
            bytes1(uint8(MessageType.FinTransfer)),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            Borsh.encodeString(payload.feeRecipient)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
```text
    function initTransferExtension(
        address sender,
        address tokenAddress,
        uint64 originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```
