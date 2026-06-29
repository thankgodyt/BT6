### Title
Native ETH `finTransfer` Always Reverts in `OmniBridgeWormhole` Due to Incorrect `msg.value` Forwarding — (`evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

---

### Summary

`OmniBridgeWormhole.finTransferExtension` forwards the full `msg.value` to the Wormhole `publishMessage` call. However, when the transfer involves native ETH (`payload.tokenAddress == address(0)`), the base `OmniBridge.finTransfer` has already spent `payload.amount` wei sending ETH to the recipient before `finTransferExtension` is invoked. The contract's remaining balance is only `msg.value - payload.amount`, so the Wormhole call reverts due to insufficient ETH. This makes every native ETH cross-chain finalization via the Wormhole path permanently impossible, freezing the locked ETH on the source chain.

---

### Finding Description

`OmniBridge.finTransfer` is `payable` and handles native ETH transfers in its first branch:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

After this branch executes, the contract's ETH balance is reduced by `payload.amount`. Control then passes to `finTransferExtension`, which in `OmniBridgeWormhole` is:

```solidity
function finTransferExtension(
    BridgeTypes.TransferMessagePayload memory payload
) internal override {
    ...
    _wormhole.publishMessage{value: msg.value}(
        wormholeNonce,
        messagePayload,
        _consistencyLevel
    );
    ...
}
``` [2](#0-1) 

`msg.value` is the **total** ETH attached to the transaction, not the **remaining** ETH after the recipient payment. After `payload.amount` has been forwarded to the recipient, the contract holds only `msg.value - payload.amount` wei. Attempting to forward `msg.value` to Wormhole will always revert with an out-of-funds error when `payload.amount > 0`.

By contrast, `initTransferExtension` correctly computes the residual value before forwarding it to Wormhole:

```solidity
extensionValue = msg.value - amount - nativeFee;
``` [3](#0-2) 

```solidity
_wormhole.publishMessage{value: value}(...)
``` [4](#0-3) 

`finTransferExtension` lacks the equivalent subtraction, making the two paths asymmetric.

---

### Impact Explanation

- A user initiates a native ETH bridge transfer by calling `initTransfer` with `tokenAddress == address(0)` on a Wormhole-enabled chain (e.g., Arbitrum, Base). The ETH is locked inside the `OmniBridgeWormhole` contract on the source chain.
- A relayer attempts to call `finTransfer` on the destination `OmniBridgeWormhole`. The call always reverts because `finTransferExtension` tries to forward `msg.value` to Wormhole after `payload.amount` has already been spent.
- Because the entire transaction reverts, `completedTransfers[payload.destinationNonce]` is never durably set, so the nonce is not consumed — but the ETH remains locked on the source chain with no cancellation or withdrawal path visible in the contract.
- **Result: permanent freezing of all bridged native ETH routed through `OmniBridgeWormhole`.** [5](#0-4) 

---

### Likelihood Explanation

Any unprivileged user who calls `initTransfer(address(0), ...)` on a deployed `OmniBridgeWormhole` instance triggers the freeze. No special role, key, or collusion is required. The Wormhole variant is deployed on Arbitrum and Base (where the native token is ETH), making this path reachable in production.

---

### Recommendation

In `finTransferExtension`, compute the Wormhole fee as the ETH remaining after the recipient payment, mirroring the pattern used in `initTransferExtension`:

```solidity
function finTransferExtension(
    BridgeTypes.TransferMessagePayload memory payload
) internal override {
    uint256 wormholeFee = payload.tokenAddress == address(0)
        ? msg.value - payload.amount
        : msg.value;

    bytes memory messagePayload = ...;
    _wormhole.publishMessage{value: wormholeFee}(
        wormholeNonce,
        messagePayload,
        _consistencyLevel
    );
    wormholeNonce++;
}
``` [2](#0-1) 

---

### Proof of Concept

1. Deploy `OmniBridgeWormhole` on a testnet (e.g., Arbitrum Sepolia).
2. Call `initTransfer(address(0), 1 ether, 0, nativeFee, recipient, "")` with `msg.value = 1 ether + nativeFee`. ETH is locked in the contract.
3. A relayer calls `finTransfer(sig, payload)` where `payload.tokenAddress == address(0)` and `payload.amount == 1 ether`, attaching `msg.value = 1 ether + wormholeFee`.
4. The base `finTransfer` sends `1 ether` to the recipient (contract balance drops to `wormholeFee`).
5. `finTransferExtension` attempts `_wormhole.publishMessage{value: msg.value}(...)` = `{value: 1 ether + wormholeFee}` — reverts because only `wormholeFee` remains.
6. The entire transaction reverts; the source-chain ETH remains permanently locked. [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-322)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L391-391)
```text
            extensionValue = msg.value - amount - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
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
