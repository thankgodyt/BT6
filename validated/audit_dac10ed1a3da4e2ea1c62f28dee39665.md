### Title
`logMetadata` and `logMetadata1155` Are Unnecessarily `payable`, Permanently Trapping Sent ETH — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`logMetadata` and `logMetadata1155` in `OmniBridge.sol` are declared `external payable` but perform no ETH operations. In the base `OmniBridge` deployment, any ETH attached to these calls is permanently locked in the contract with no recovery path.

### Finding Description
Both functions are publicly callable with no access control and no signature requirement: [1](#0-0) [2](#0-1) 

Neither function references `msg.value` anywhere in its body. The only ETH-related hook is `logMetadataExtension`, which in the base `OmniBridge` is a virtual no-op: [3](#0-2) 

The contract has a bare `receive()` function but no ETH withdrawal mechanism, so any ETH sent to these calls is permanently irrecoverable: [4](#0-3) 

In `OmniBridgeWormhole`, `logMetadataExtension` does forward `msg.value` to the Wormhole `publishMessage` call, so the issue is specific to the base `OmniBridge` deployment path: [5](#0-4) 

### Impact Explanation
Any user who calls `logMetadata(tokenAddress)` or `logMetadata1155(tokenAddress, tokenId)` while attaching ETH (e.g., mistaking it for a fee-bearing call, or using a wallet that auto-attaches value) permanently loses that ETH. The contract has no admin withdrawal function for accidentally received ETH. This constitutes a direct, permanent loss of user funds with no recovery path — matching the "loss of bridged/user funds" critical impact class.

### Likelihood Explanation
Both functions are permissionless entry points callable by any unprivileged user. Token deployers and bridge users routinely call `logMetadata` to register token metadata before initiating cross-chain transfers. The `payable` modifier creates a false expectation that a fee is required or accepted, making accidental ETH attachment realistic. Wallets and scripts that pass `value` to all bridge-interaction calls would silently lose funds.

### Recommendation
Remove the `payable` modifier from both `logMetadata` and `logMetadata1155` in `OmniBridge.sol`. If Wormhole fee forwarding is needed in `OmniBridgeWormhole`, override these functions there and add `payable` only in the subclass, not in the base contract.

### Proof of Concept
1. Deploy the base `OmniBridge` contract (non-Wormhole variant).
2. Call `logMetadata(someERC20Address)` with `{value: 1 ether}`.
3. The transaction succeeds (no revert), the `LogMetadata` event is emitted, and `1 ether` is now held by the contract.
4. No function exists to recover the ETH — it is permanently locked. [1](#0-0) [6](#0-5)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L272-277)
```text
    function logMetadataExtension(
        address tokenAddress,
        string memory name,
        string memory symbol,
        uint8 decimals
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L72-93)
```text
    function logMetadataExtension(
        address tokenAddress,
        string memory name,
        string memory symbol,
        uint8 decimals
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.LogMetadata)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeString(name),
            Borsh.encodeString(symbol),
            bytes1(decimals)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
```
