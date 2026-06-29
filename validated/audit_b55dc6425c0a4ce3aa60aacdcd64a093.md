### Title
Excess ETH Not Refunded to Caller in `OmniBridgeWormhole` Payable Functions - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

### Summary
`OmniBridgeWormhole` overrides the extension hooks for `deployToken`, `logMetadata`/`logMetadata1155`, and `finTransfer` to forward the caller's full `msg.value` directly to Wormhole's `publishMessage`. No check enforces that `msg.value` equals exactly `wormhole.messageFee()`, and no excess is refunded. Any ETH above the required Wormhole fee is permanently transferred to the Wormhole core bridge contract and irrecoverable by the caller.

### Finding Description
`OmniBridgeWormhole` inherits from `OmniBridge` and overrides three internal extension hooks:

**`deployTokenExtension`** — called from `OmniBridge.deployToken` (which is `external payable`): [1](#0-0) 

**`logMetadataExtension`** — called from `OmniBridge.logMetadata` and `logMetadata1155` (both `external payable`): [2](#0-1) 

**`finTransferExtension`** — called from `OmniBridge.finTransfer` (which is `external payable`): [3](#0-2) 

In all three cases, the full `msg.value` is forwarded verbatim to `_wormhole.publishMessage`. The Wormhole interface exposes `messageFee()` for querying the required fee: [4](#0-3) 

Neither the base `OmniBridge` entry points nor the Wormhole extension hooks validate that `msg.value == _wormhole.messageFee()`. The base `logMetadata` and `logMetadata1155` entry points perform no ETH accounting at all: [5](#0-4) [6](#0-5) 

Similarly, `deployToken` is `external payable` with no excess-ETH guard: [7](#0-6) 

For `initTransfer` with ERC20 tokens, the `extensionValue = msg.value - nativeFee` is forwarded to Wormhole. If `msg.value - nativeFee > _wormhole.messageFee()`, the excess is also lost: [8](#0-7) [9](#0-8) 

### Impact Explanation
Any ETH sent above `_wormhole.messageFee()` is permanently transferred to the Wormhole core bridge contract. The caller has no mechanism to recover it. This constitutes a direct, irreversible loss of user funds — a fee mis-accounting issue matching the Critical impact category. When the Wormhole fee is 0 (its current mainnet value), any non-zero `msg.value` sent to `logMetadata`, `logMetadata1155`, or `deployToken` is entirely lost.

### Likelihood Explanation
These are permissionless, publicly callable functions. Any token deployer or metadata logger interacting with the Wormhole-variant bridge is exposed. Users who send a "safe" overpayment to guarantee transaction success (a common pattern), or who use a stale fee estimate, will silently lose the excess. The Wormhole fee can also change over time, making exact-fee knowledge non-trivial.

### Recommendation
Add an explicit check in each Wormhole extension hook (or in the base entry points before calling the extension) that `msg.value == _wormhole.messageFee()`, and revert with a descriptive error if not. Alternatively, compute the exact required fee and refund any excess to `msg.sender` after the `publishMessage` call. For `initTransfer`, enforce `msg.value - nativeFee == _wormhole.messageFee()`.

```solidity
// Example fix for logMetadataExtension:
function logMetadataExtension(...) internal override {
    uint256 fee = _wormhole.messageFee();
    require(msg.value == fee, "InvalidWormholeFee");
    _wormhole.publishMessage{value: fee}(...);
}
```

### Proof of Concept
1. Deploy `OmniBridgeWormhole` pointing to a real Wormhole core bridge where `messageFee() == X`.
2. Call `logMetadata(tokenAddress)` with `msg.value = X + 1 ether`.
3. `logMetadataExtension` executes `_wormhole.publishMessage{value: X + 1 ether}(...)`.
4. Wormhole accepts the call (fee satisfied), retaining `X + 1 ether`.
5. The caller's `1 ether` excess is permanently locked in the Wormhole contract with no refund path.

The same applies to `deployToken` and `finTransfer` with any `msg.value > messageFee()`, and to `initTransfer` (ERC20 path) when `msg.value - nativeFee > messageFee()`.

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L62-67)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L86-93)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L108-115)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );

        wormholeNonce++;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L142-147)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-138)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-270)
```text
    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        MultiTokenInfo storage multiToken = multiTokens[deterministicToken];

        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
        } else {
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
        }

        logMetadataExtension(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );

        emit BridgeTypes.LogMetadata(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L392-393)
```text
        } else {
            extensionValue = msg.value - nativeFee;
```
