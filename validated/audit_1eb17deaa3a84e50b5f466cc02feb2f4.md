### Title
Wormhole `publishMessage` Fee Forwarding Fails for Native ETH `finTransfer` Due to Double-Spending of `msg.value` - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

---

### Summary

In `OmniBridgeWormhole.finTransferExtension`, the Wormhole `publishMessage` is called with `{value: msg.value}`. However, when the transfer involves native ETH (`tokenAddress == address(0)`), the base `finTransfer` function has already spent `payload.amount` ETH by sending it to the recipient before `finTransferExtension` is invoked. The contract's remaining balance is only `msg.value - payload.amount`, making the `{value: msg.value}` call to Wormhole always revert. This permanently blocks finalization of all native ETH transfers on the Wormhole path.

---

### Finding Description

`OmniBridge.finTransfer` is `payable` and handles native ETH delivery to the recipient before calling the extension hook:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
// ...
finTransferExtension(payload);   // <-- called after ETH is already spent
``` [1](#0-0) [2](#0-1) 

`OmniBridgeWormhole.finTransferExtension` then unconditionally forwards the full original `msg.value` to Wormhole:

```solidity
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
``` [3](#0-2) 

At the point `finTransferExtension` executes, the contract's ETH balance is `msg.value - payload.amount` (the `payload.amount` portion was already transferred to the recipient). Attempting to forward `msg.value` ETH to Wormhole will always revert with an insufficient-balance error when `payload.amount > 0`.

The Wormhole interface enforces an exact fee check:

```solidity
require(msg.value == this.messageFee(), "invalid fee");
``` [4](#0-3) 

So even if the contract somehow had enough ETH, forwarding `msg.value` (which includes `payload.amount`) instead of just the Wormhole `messageFee()` would still cause a revert.

---

### Impact Explanation

Every call to `finTransfer` on `OmniBridgeWormhole` where `payload.tokenAddress == address(0)` (native ETH) will revert at the Wormhole `publishMessage` step. This permanently prevents finalization of any native ETH transfer from NEAR to an EVM chain via the Wormhole path. Funds that users locked/burned on the NEAR side expecting ETH delivery on the EVM side cannot be released. This constitutes permanent freezing of bridged ETH.

---

### Likelihood Explanation

Any relayer or user attempting to call `finTransfer` for a native ETH payload on the Wormhole variant triggers this revert deterministically. No special conditions are required — the bug is hit on every such call. The `finTransfer` function has no access control, so any party can attempt it and observe the failure. [5](#0-4) 

---

### Recommendation

In `finTransferExtension`, compute the Wormhole fee separately from the ETH amount owed to the recipient. One approach:

```solidity
function finTransferExtension(
    BridgeTypes.TransferMessagePayload memory payload
) internal override {
    uint256 wormholeFee = _wormhole.messageFee();
    // ...
    _wormhole.publishMessage{value: wormholeFee}(
        wormholeNonce,
        messagePayload,
        _consistencyLevel
    );
}
```

The caller of `finTransfer` must supply `msg.value = payload.amount + wormholeFee` for native ETH transfers, and the extension must forward only `wormholeFee` to Wormhole, not the full `msg.value`.

---

### Proof of Concept

1. Deploy `OmniBridgeWormhole` with a Wormhole mock that charges `messageFee = 10000 wei`.
2. Prepare a valid `TransferMessagePayload` with `tokenAddress = address(0)` and `amount = 1 ether`.
3. Call `finTransfer{value: 1 ether + 10000}(sig, payload)`.
4. The base contract sends `1 ether` to `payload.recipient` — contract balance is now `10000 wei`.
5. `finTransferExtension` calls `_wormhole.publishMessage{value: 1 ether + 10000}(...)`.
6. The EVM reverts: contract has only `10000 wei` but is trying to forward `1 ether + 10000 wei`.
7. The transfer is permanently unfinalizeable. [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L13-13)
```text
        require(msg.value == this.messageFee(), "invalid fee");
```
