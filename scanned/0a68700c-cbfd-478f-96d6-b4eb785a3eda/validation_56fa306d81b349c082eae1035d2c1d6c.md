### Title
`OmniBridgeWormhole.finTransfer` Always Reverts for Native ETH (`address(0)`) Transfers Due to Incorrect `msg.value` Forwarding to Wormhole - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

---

### Summary

`OmniBridgeWormhole.finTransferExtension` unconditionally forwards the full `msg.value` to the Wormhole `publishMessage` call. When `payload.tokenAddress == address(0)` (native ETH), the base `finTransfer` function first spends `payload.amount` of that ETH sending it to the recipient, leaving only `msg.value - payload.amount` in the contract. The subsequent attempt to forward the original `msg.value` to Wormhole then reverts due to insufficient ETH balance, permanently blocking all native ETH bridge completions on Wormhole-connected chains.

---

### Finding Description

In `OmniBridge.finTransfer`, `address(0)` is the sentinel for native ETH:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
// ...
finTransferExtension(payload);   // called unconditionally after ETH is already spent
``` [1](#0-0) 

`OmniBridgeWormhole.finTransferExtension` then forwards the **full original `msg.value`** to Wormhole:

```solidity
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
``` [2](#0-1) 

After `payload.amount` ETH has already been sent to the recipient, the contract only holds `msg.value - payload.amount` ETH. Forwarding `msg.value` to Wormhole exceeds the available balance and the EVM reverts the entire transaction.

Contrast this with `initTransfer`, which correctly computes the residual value before calling the extension:

```solidity
if (tokenAddress == address(0)) {
    extensionValue = msg.value - amount - nativeFee;   // ETH for token + fee subtracted
} else {
    extensionValue = msg.value - nativeFee;
}
// ...
initTransferExtension(..., extensionValue);   // only the remainder is forwarded
``` [3](#0-2) 

And in `OmniBridgeWormhole.initTransferExtension`, the `value` parameter (not `msg.value`) is used:

```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [4](#0-3) 

The `finTransfer` path has no equivalent residual-value computation; it passes `msg.value` raw.

---

### Impact Explanation

**Critical.** Every call to `OmniBridgeWormhole.finTransfer` where `payload.tokenAddress == address(0)` will revert unconditionally. Relayers cannot complete native ETH transfers from NEAR to any Wormhole-connected EVM chain. Funds locked on the NEAR side for such transfers can never be released on the destination chain, constituting permanent freezing of bridged ETH.

---

### Likelihood Explanation

**High.** Native ETH (`address(0)`) is explicitly supported as a bridgeable asset — the `finTransfer` function contains a dedicated branch for it, and `initTransfer` also handles it. Any user who initiates a NEAR → EVM native ETH transfer will have their funds permanently stuck because the finalization step always reverts on `OmniBridgeWormhole`.

---

### Recommendation

Compute the residual ETH value in `finTransfer` before calling `finTransferExtension`, mirroring the pattern used in `initTransfer`:

```solidity
// In OmniBridge.finTransfer, before calling finTransferExtension:
uint256 extensionValue = (payload.tokenAddress == address(0))
    ? msg.value - payload.amount   // ETH already sent to recipient
    : msg.value;

finTransferExtension(payload, extensionValue);
```

Update `finTransferExtension` signatures in both `OmniBridge` and `OmniBridgeWormhole` to accept and use this `extensionValue` instead of `msg.value`.

---

### Proof of Concept

1. Deploy `OmniBridgeWormhole` on an EVM chain.
2. Call `finTransfer` with `payload.tokenAddress = address(0)` and `payload.amount = 1 ether`, sending `msg.value = 1 ether + wormholeFee`.
3. The base contract sends `1 ether` to `payload.recipient` (succeeds).
4. `finTransferExtension` attempts `_wormhole.publishMessage{value: msg.value}(...)` — i.e., `{value: 1 ether + wormholeFee}` — but the contract only holds `wormholeFee` ETH.
5. The EVM reverts with an out-of-funds error, rolling back the entire transaction including the ETH transfer to the recipient.
6. The nonce is marked `completedTransfers[payload.destinationNonce] = true` before the revert is reached, so the transfer cannot be retried. [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-357)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L387-425)
```text
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L143-147)
```text
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```
