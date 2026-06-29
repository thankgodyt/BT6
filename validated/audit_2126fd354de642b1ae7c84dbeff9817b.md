### Title
ETH Mistakenly Sent with ERC20-Based `finTransfer` Calls Will Be Permanently Locked — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`finTransfer` in `OmniBridge.sol` is `payable` but never validates or consumes `msg.value` when the transfer token is not native ETH (`payload.tokenAddress != address(0)`). Any ETH sent alongside an ERC20, ERC1155, or bridge-token `finTransfer` call is permanently locked in the contract. The base contract's `finTransferExtension` is a no-op, so there is no guard equivalent to the one that already exists in `initTransferExtension`.

---

### Finding Description

`finTransfer` is declared `payable` at line 282 to support the `OmniBridgeWormhole` subclass, which overrides `finTransferExtension` to forward `msg.value` to the Wormhole relayer as a publishing fee. [1](#0-0) 

In the base `OmniBridge.sol` (deployed for MPC-verified chains), `finTransferExtension` is a no-op: [2](#0-1) 

When `payload.tokenAddress != address(0)`, the function performs an ERC20/ERC1155/mint transfer and then calls the no-op extension — `msg.value` is never used, checked, or refunded: [3](#0-2) 

By contrast, `initTransferExtension` in the same base contract explicitly reverts if `value != 0`, preventing excess ETH from being locked: [4](#0-3) 

This asymmetry is the root cause. The ETH-transfer path in `finTransfer` also does **not** consume `msg.value` — it sends `payload.amount` ETH from the contract's own accumulated balance, not from the caller's attached value: [5](#0-4) 

This makes it non-obvious to callers that `msg.value` is never consumed in any code path of the base contract's `finTransfer`.

---

### Impact Explanation

Any ETH attached to a non-ETH `finTransfer` call is permanently locked in the contract. There is no withdrawal function, no refund path, and no recovery mechanism for mistakenly sent ETH. This constitutes permanent freezing of user funds, matching the critical/medium impact class of the reference vulnerability.

---

### Likelihood Explanation

`finTransfer` is the single entry point for finalizing both ETH and ERC20 bridge transfers. A relayer (or any caller holding a valid MPC signature) operating across both token types may accidentally attach ETH when finalizing an ERC20 transfer — especially because the ETH-transfer path superficially appears to require ETH from the caller, when in fact it draws from the contract's locked balance. The same function signature is used for all token types, making the mistake realistic and the probability non-negligible, exactly as in the reference report.

---

### Recommendation

Add a `msg.value == 0` guard to the base `finTransferExtension`, mirroring the existing guard in `initTransferExtension`:

```solidity
function finTransferExtension(
    BridgeTypes.TransferMessagePayload memory payload
) internal virtual {
    if (msg.value != 0) {
        revert InvalidValue();
    }
}
```

`OmniBridgeWormhole` already overrides this function to forward `msg.value` to Wormhole, so the override is unaffected. [6](#0-5) 

---

### Proof of Concept

1. A relayer finalizes an ERC20 bridge transfer by calling `finTransfer` on the base `OmniBridge` deployment with a valid MPC signature and `payload.tokenAddress = <ERC20 address>`.
2. The relayer accidentally includes `msg.value = 1 ether`.
3. The contract verifies the signature and executes `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)`.
4. `finTransferExtension(payload)` is called — it is a no-op.
5. The 1 ETH is permanently locked in the contract. No event is emitted for it, no refund occurs, and no admin function exists to recover it. [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L323-371)
```text
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

    function finTransferExtension(
        BridgeTypes.TransferMessagePayload memory payload
    ) internal virtual {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L492-506)
```text
    function initTransferExtension(
        address /*sender*/,
        address /*tokenAddress*/,
        uint64 /*originNonce*/,
        uint128 /*amount*/,
        uint128 /*fee*/,
        uint128 /*nativeFee*/,
        string calldata /*recipient*/,
        string calldata /*message*/,
        uint256 value
    ) internal virtual {
        if (value != 0) {
            revert InvalidValue();
        }
    }
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
