### Title
Excess `msg.value` Permanently Locked Due to Missing Validation in `OmniBridge::finTransfer()` and Related Payable Functions - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::finTransfer()` is declared `external payable` but contains no validation that `msg.value == 0` in the base contract deployment (Ethereum, light-client path). The `finTransferExtension` hook is a virtual no-op in the base contract, so any ETH attached to a `finTransfer` call is silently absorbed into the contract balance with no refund and no recovery path. The same pattern applies to `logMetadata` and `logMetadata1155`. In `OmniBridgeWormhole`, `finTransferExtension` forwards the raw `msg.value` to Wormhole without validating it equals `_wormhole.messageFee()`, causing any excess to be permanently sent to Wormhole's fee collector.

---

### Finding Description

**Root cause — base `OmniBridge` (Ethereum deployment):**

`finTransfer` is marked `payable`: [1](#0-0) 

After disbursing tokens/ETH to the recipient it calls `finTransferExtension(payload)`: [2](#0-1) 

In the base contract, `finTransferExtension` is a virtual no-op: [3](#0-2) 

There is no `require(msg.value == 0)`, no refund to `msg.sender`, and no administrative ETH-withdrawal function anywhere in the contract. Any ETH attached to the call is permanently locked.

The same pattern exists for `logMetadata` and `logMetadata1155`, both `payable` with a no-op `logMetadataExtension` in the base contract: [4](#0-3) [5](#0-4) 

**Root cause — `OmniBridgeWormhole` (Wormhole-routed chains):**

`finTransferExtension` forwards the raw `msg.value` to Wormhole without checking it equals `_wormhole.messageFee()`: [6](#0-5) 

The Wormhole interface exposes `messageFee()` for exactly this purpose: [7](#0-6) 

If `msg.value > messageFee()`, the excess is forwarded to Wormhole's fee collector and is unrecoverable by the caller. The `initTransferExtension` path in `OmniBridgeWormhole` passes the computed `extensionValue` (not raw `msg.value`) to Wormhole, so it is less exposed, but `finTransferExtension`, `deployTokenExtension`, and `logMetadataExtension` all use raw `msg.value`: [8](#0-7) [9](#0-8) 

**Contrast with `initTransfer` (correctly protected in base `OmniBridge`):**

The base `initTransferExtension` reverts if `value != 0`, so `initTransfer` is properly guarded: [10](#0-9) 

`finTransfer` and the metadata functions have no equivalent guard.

---

### Impact Explanation

- **Base `OmniBridge` (Ethereum):** Any ETH attached to `finTransfer`, `logMetadata`, or `logMetadata1155` is permanently locked in the contract. There is no `receive`/`fallback` withdrawal path. This constitutes a permanent, irreversible loss of user or relayer ETH — a balance manipulation that changes user balances with no recovery.
- **`OmniBridgeWormhole`:** Any ETH sent above `messageFee()` to `finTransfer`, `deployToken`, or `logMetadata` is permanently forwarded to Wormhole's fee collector and lost to the caller.

---

### Likelihood Explanation

Low. A relayer or user calling `finTransfer` on the base `OmniBridge` (Ethereum) has no protocol reason to attach ETH. However, for `OmniBridgeWormhole`, relayers must attach exactly `messageFee()` ETH; a stale fee estimate or off-by-one error causes permanent loss. The `logMetadata` and `logMetadata1155` functions are callable by anyone with no access control, widening the exposure surface.

---

### Recommendation

1. **Base `OmniBridge`:** Remove the `payable` modifier from `finTransfer`, `logMetadata`, and `logMetadata1155`, or add `require(msg.value == 0, "InvalidValue")` at the top of each.
2. **`OmniBridgeWormhole`:** In `finTransferExtension`, `deployTokenExtension`, and `logMetadataExtension`, validate `msg.value == _wormhole.messageFee()` before forwarding, mirroring the pattern already used in `initTransferExtension` (which correctly passes a pre-computed `value` rather than raw `msg.value`).
3. Consider adding an emergency ETH-recovery function restricted to `DEFAULT_ADMIN_ROLE` as a backstop.

---

### Proof of Concept

**Base `OmniBridge` (Ethereum):**
1. Deploy `OmniBridge` (base contract, Ethereum light-client deployment).
2. Obtain a valid MPC-signed `(signatureData, payload)` for any ERC-20 `finTransfer`.
3. Call `OmniBridge.finTransfer(signatureData, payload)` with `{value: 1 ether}`.
4. The call succeeds: the nonce is marked used, tokens are minted/transferred to the recipient, the `FinTransfer` event is emitted.
5. The 1 ETH is now in the contract's balance with no function to retrieve it.

**`OmniBridgeWormhole`:**
1. Obtain a valid `(signatureData, payload)` for a `finTransfer`.
2. Call `OmniBridgeWormhole.finTransfer(signatureData, payload)` with `{value: messageFee() + 1 ether}`.
3. The call succeeds; `messageFee() + 1 ether` is forwarded to Wormhole's `publishMessage`.
4. The 1 ETH excess is absorbed by Wormhole's fee collector and is unrecoverable.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L272-277)
```text
    function logMetadataExtension(
        address tokenAddress,
        string memory name,
        string memory symbol,
        uint8 decimals
    ) internal virtual {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L357-357)
```text
        finTransferExtension(payload);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L369-371)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L8-16)
```text
interface IWormhole {
    function publishMessage(
        uint32 nonce,
        bytes memory payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    function messageFee() external view returns (uint256);
}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L62-63)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L86-87)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
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
