### Title
`OmniBridge` Contract Accepts ETH via `receive()` But Provides No ETH Rescue/Withdrawal Function — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol` declares `receive() external payable {}`, making the contract capable of accepting raw ETH transfers. However, neither `OmniBridge` nor its deployed subclass `OmniBridgeWormhole` implements any `rescueETH()`, `withdrawETH()`, or equivalent admin-callable function. Any ETH sent directly to the contract address — outside of the structured `initTransfer` flow — is permanently locked with no on-chain recovery path.

---

### Finding Description

`OmniBridge.sol` line 574 declares:

```solidity
receive() external payable {}
``` [1](#0-0) 

This makes the contract unconditionally accept raw ETH. The only path by which ETH ever leaves the contract is inside `finTransfer`, and only when `payload.tokenAddress == address(0)`:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [2](#0-1) 

That path requires a valid MPC-signed `TransferMessagePayload` verified against `nearBridgeDerivedAddress`. There is no admin-callable function to recover ETH that arrives via the `receive()` fallback outside of the bridge flow.

A search across all EVM Solidity files confirms zero occurrences of `rescueETH`, `rescueERC20`, `emergencyWithdraw`, or any equivalent pattern. [3](#0-2) 

`OmniBridgeWormhole`, the only deployed subclass, adds no rescue capability either: [4](#0-3) 

---

### Impact Explanation

Any ETH sent directly to the contract address — by a user who mistakes the bridge contract for a payable endpoint, by a wallet that sends ETH before calling `initTransfer`, or by any other accidental direct transfer — is permanently frozen. Because the only ETH-release path (`finTransfer` with `tokenAddress == address(0)`) requires a valid MPC signature over a specific `TransferMessagePayload`, there is no administrative or user-initiated mechanism to recover the stuck ETH. This constitutes a permanent, irrecoverable loss of user funds.

---

### Likelihood Explanation

The `receive()` function is publicly reachable by any EOA or contract. Users interacting with a bridge contract that handles native ETH (as `initTransfer` with `tokenAddress == address(0)` does) may reasonably attempt to send ETH directly to the contract address. Wallets, scripts, and integrations that pre-fund a contract before calling a function are common patterns. The likelihood of accidental direct ETH sends to a bridge contract that explicitly advertises ETH support is realistic.

---

### Recommendation

Add an admin-restricted ETH rescue function, analogous to the `rescueERC20()` pattern referenced in the external report:

```solidity
function rescueETH(address payable to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
    (bool success, ) = to.call{value: amount}("");
    require(success, "ETH rescue failed");
}
```

This should be added to `OmniBridge.sol` so it is inherited by all deployed variants including `OmniBridgeWormhole`.

---

### Proof of Concept

1. Deploy `OmniBridgeWormhole` (or `OmniBridge`) normally.
2. As any unprivileged EOA, execute:
   ```solidity
   (bool ok,) = address(omniBridge).call{value: 1 ether}("");
   // ok == true, ETH is now in the contract
   ```
3. Observe `address(omniBridge).balance == 1 ether`.
4. Attempt any recovery — no function exists. The ETH is permanently locked.

The `receive() external payable {}` at line 574 of `OmniBridge.sol` is the sole root cause; the absence of any rescue function is confirmed by a full grep of all EVM Solidity sources. [1](#0-0)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-596)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }

    function upgradeToken(
        address tokenAddress,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isBridgeToken[tokenAddress], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(tokenAddress);
        proxy.upgradeToAndCall(implementation, bytes(""));
    }

    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }

    receive() external payable {}

    function deriveDeterministicAddress(
        address tokenAddress,
        uint256 tokenId
    ) public pure returns (address) {
        return
            address(
                bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId)))
            );
    }

    function _normalizeDecimals(uint8 decimals) internal pure returns (uint8) {
        uint8 maxAllowedDecimals = 18;
        if (decimals > maxAllowedDecimals) {
            return maxAllowedDecimals;
        }
        return decimals;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L26-159)
```text
contract OmniBridgeWormhole is OmniBridge {
    IWormhole private _wormhole;
    // https://wormhole.com/docs/build/reference/consistency-levels
    uint8 private _consistencyLevel;
    uint32 public wormholeNonce;

    function initializeWormhole(
        address tokenImplementationAddress,
        address nearBridgeDerivedAddress,
        uint8 omniBridgeChainId,
        address wormholeAddress,
        uint8 consistencyLevel
    ) external initializer {
        initialize(
            tokenImplementationAddress,
            nearBridgeDerivedAddress,
            omniBridgeChainId
        );
        _wormhole = IWormhole(wormholeAddress);
        _consistencyLevel = consistencyLevel;
    }

    function deployTokenExtension(
        string memory token,
        address tokenAddress,
        uint8 decimals,
        uint8 originDecimals
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.DeployToken)),
            Borsh.encodeString(token),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            bytes1(decimals),
            bytes1(originDecimals)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }

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
    }

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

    function setWormholeAddress(
        address wormholeAddress,
        uint8 consistencyLevel
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _wormhole = IWormhole(wormholeAddress);
        _consistencyLevel = consistencyLevel;
    }
}
```
