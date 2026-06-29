Audit Report

## Title
`nativeFee` ETH Permanently Locked With No On-Chain Claim Mechanism - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`OmniBridge.initTransfer` and `initTransfer1155` subtract `nativeFee` from `msg.value` before forwarding only `extensionValue` to `initTransferExtension`. The `nativeFee` portion accumulates in the contract's ETH balance. Although `BridgeTypes.PayloadType` defines a `ClaimNativeFee` enum variant, no function in `OmniBridge.sol` or `OmniBridgeWormhole.sol` handles or processes this payload type, leaving the accumulated ETH permanently unrecoverable.

## Finding Description
In `initTransfer`, `extensionValue` is computed as `msg.value - amount - nativeFee` (native-ETH path) or `msg.value - nativeFee` (ERC-20 path), and only `extensionValue` is passed to `initTransferExtension`. [1](#0-0) 

In `OmniBridgeWormhole.initTransferExtension`, only `value` (i.e., `extensionValue`) is forwarded to Wormhole's `publishMessage`; the `nativeFee` portion is never forwarded, never credited to a relayer, and never emitted as a claimable balance. [2](#0-1) 

`BridgeTypes.PayloadType` defines `ClaimNativeFee` as payload type `2`, indicating the protocol intended a cross-chain claim path for these fees. [3](#0-2) 

However, a full review of `OmniBridge.sol` and `OmniBridgeWormhole.sol` confirms that no function parses or acts on a `ClaimNativeFee` payload. The only inbound message handler is `finTransfer`, which exclusively processes `TransferMessagePayload` structs and makes no payment to any relayer from the accumulated ETH pool. [4](#0-3) 

The bare `receive()` function further allows unsolicited ETH to enter the contract with no recovery path. [5](#0-4) 

No `withdraw`, `rescueETH`, or admin-recovery function exists anywhere in the contract or its inheritance chain.

## Impact Explanation
Every `initTransfer` / `initTransfer1155` call with `nativeFee > 0` permanently locks that ETH in the contract. Because `nativeFee` is the mechanism by which users compensate relayers for EVM-side gas, this fee is expected to be non-zero in normal bridge operation. The ETH is not lost due to an edge case; it is lost on every standard bridge transfer. This constitutes **fee mis-accounting** — a concrete, on-chain accounting error that permanently destroys user-paid ETH — matching the Critical allowed impact: *"fee mis-accounting… that changes user or protocol balances."*

## Likelihood Explanation
Any unprivileged user calling `initTransfer` or `initTransfer1155` with `nativeFee > 0` triggers the loss. No special conditions, admin access, or error state is required. The loss is automatic and continuous across all bridge usage. The `ClaimNativeFee` payload type being defined but unimplemented confirms this is not a deliberate design choice but a missing implementation.

## Recommendation
1. Implement a `claimNativeFee` function in `OmniBridge.sol` that verifies a signed `ClaimNativeFee` payload from `nearBridgeDerivedAddress` and transfers the specified ETH amount to the designated relayer/fee-recipient address, consistent with the already-defined `PayloadType.ClaimNativeFee`.
2. Alternatively, forward `nativeFee` directly to a designated `feeRecipient` address inside `initTransfer` at call time, eliminating the need for a separate claim step.
3. Remove or revert-guard the bare `receive()` function if the contract is not intended to accept unsolicited ETH.

## Proof of Concept
1. Deploy `OmniBridgeWormhole` with a stub `TestWormhole` (already present in the test suite).
2. Call `initTransfer(erc20Token, 1e18, 0, 0.01 ether, "recipient.near", "")` with `msg.value = 0.01 ether`.
3. Observe: `extensionValue = 0.01 ether - 0.01 ether = 0`; `_wormhole.publishMessage{value: 0}(...)` is called; contract ETH balance increases by `0.01 ether`.
4. Repeat for N transfers. Contract ETH balance grows monotonically by `N * nativeFee`.
5. Confirm: no function in `OmniBridge.sol` or `OmniBridgeWormhole.sol` can move this ETH out. The `ClaimNativeFee` payload type (enum value `2`) is defined in `BridgeTypes.PayloadType` but has zero handling code in any EVM contract, confirming the recovery path is absent.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }

        finTransferExtension(payload);

        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L391-393)
```text
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L143-147)
```text
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L67-71)
```text
    enum PayloadType {
        TransferMessage,
        Metadata,
        ClaimNativeFee
    }
```
