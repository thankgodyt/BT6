### Title
`finTransferExtension` Uses Full `msg.value` After Native ETH Already Sent to Recipient, Permanently Freezing Native ETH Bridge Transfers - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

### Summary

`OmniBridgeWormhole.finTransferExtension` forwards the full `msg.value` to the Wormhole `publishMessage` call. However, when the transfer is for native ETH (`tokenAddress == address(0)`), the base `finTransfer` function has already spent `payload.amount` of that ETH sending it to the recipient. The contract no longer holds `msg.value` at the point `finTransferExtension` executes, so the Wormhole call reverts. Every native ETH `finTransfer` on Wormhole-connected chains is permanently broken.

### Finding Description

`OmniBridge.finTransfer` is `payable` and, for native ETH transfers, immediately forwards `payload.amount` wei to the recipient before calling `finTransferExtension`:

```solidity
// OmniBridge.sol lines 317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
...
finTransferExtension(payload);   // called after ETH is already gone
``` [1](#0-0) 

`OmniBridgeWormhole.finTransferExtension` then tries to forward the **original** `msg.value` to Wormhole:

```solidity
// OmniBridgeWormhole.sol lines 109-113
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
``` [2](#0-1) 

At this point the contract's ETH balance is only `msg.value - payload.amount`. Attempting to send `msg.value` will always revert with an out-of-funds error when `payload.amount > 0`.

For ERC-20 transfers the same function also uses `msg.value` directly: [3](#0-2) 

For ERC-20 the full `msg.value` is still available (no ETH was spent), so that path is unaffected. The breakage is isolated to `tokenAddress == address(0)`.

Contrast with `initTransferExtension`, which correctly receives a pre-computed `value` parameter (already reduced by `amount` and `nativeFee`) and passes that to Wormhole: [4](#0-3) 

The base `initTransferExtension` computes `extensionValue = msg.value - amount - nativeFee` before passing it down: [5](#0-4) 

`finTransferExtension` has no equivalent accounting step, making the native-ETH path permanently broken.

### Impact Explanation

`OmniBridgeWormhole` is the contract deployed on Wormhole-connected chains (BNB, Arbitrum, Base, Polygon). When a user bridges native ETH (or the chain's native token) from NEAR to one of these chains, the relayer calls `finTransfer` with `msg.value = payload.amount + wormhole.messageFee()`. After the ETH is sent to the recipient, only `wormhole.messageFee()` remains, but the code tries to forward `payload.amount + wormhole.messageFee()` to Wormhole. The transaction reverts every time. The source-chain lock/burn has already been recorded; the destination-chain release can never succeed. The bridged native ETH is permanently frozen.

### Likelihood Explanation

Any user who initiates a native ETH bridge transfer to a Wormhole-connected chain triggers this path. The relayer's `finTransfer` call will revert unconditionally for every such transfer. No special attacker capability is required; the bug is hit by normal bridge usage.

### Recommendation

Pass the remaining ETH (after the native transfer) to `finTransferExtension` as an explicit parameter, mirroring the pattern already used in `initTransferExtension`:

```solidity
// In OmniBridge.finTransfer:
uint256 remainingValue = msg.value;
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
    remainingValue = msg.value - payload.amount;
}
...
finTransferExtension(payload, remainingValue);
```

Then update `OmniBridgeWormhole.finTransferExtension` to accept and use that `remainingValue` instead of `msg.value`.

### Proof of Concept

1. User bridges 1 ETH from NEAR → Arbitrum (a Wormhole chain). Source side records the lock.
2. Relayer calls `OmniBridgeWormhole.finTransfer{value: 1 ETH + wormhole_fee}(sig, payload)` where `payload.tokenAddress = address(0)`, `payload.amount = 1 ETH`.
3. `finTransfer` executes `payload.recipient.call{value: 1 ETH}("")` — succeeds; contract balance is now `wormhole_fee`.
4. `finTransferExtension` executes `_wormhole.publishMessage{value: msg.value}(...)` where `msg.value = 1 ETH + wormhole_fee` — **reverts** because the contract only holds `wormhole_fee`.
5. The entire transaction reverts. The recipient never receives ETH. The relayer retries and fails identically. The 1 ETH is permanently frozen. [6](#0-5) [3](#0-2)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L387-393)
```text
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-149)
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
```
