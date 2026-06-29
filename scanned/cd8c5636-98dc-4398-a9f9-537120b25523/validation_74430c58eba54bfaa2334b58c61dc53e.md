### Title
`nativeFee` ETH Permanently Locked in `OmniBridgeWormhole` — No Withdrawal Path — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

Every call to `initTransfer` or `initTransfer1155` that carries a non-zero `nativeFee` deposits that ETH into the `OmniBridge` contract, but only the remainder (`extensionValue = msg.value - nativeFee`) is forwarded onward (to Wormhole). The `nativeFee` portion is never forwarded, never distributed, and there is no `withdraw` function anywhere in `OmniBridge.sol` or `OmniBridgeWormhole.sol` to recover it. Every wei of `nativeFee` paid by every bridge user is permanently locked.

---

### Finding Description

`initTransfer` splits `msg.value` into two parts:

```solidity
// OmniBridge.sol L392-393 (ERC-20 path)
extensionValue = msg.value - nativeFee;
``` [1](#0-0) 

Only `extensionValue` is passed to `initTransferExtension`:

```solidity
initTransferExtension(..., extensionValue);   // L415-425
``` [2](#0-1) 

In `OmniBridgeWormhole`, the override of `initTransferExtension` forwards only `value` (i.e., `extensionValue`) to Wormhole:

```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [3](#0-2) 

The `nativeFee` ETH — the difference between `msg.value` and `extensionValue` — is never forwarded anywhere. It accumulates silently in the contract balance.

The same split applies to `initTransfer1155`:

```solidity
uint256 extensionValue = msg.value - nativeFee;   // L466
``` [4](#0-3) 

A bare `receive()` further allows arbitrary ETH to be sent in with no path out:

```solidity
receive() external payable {}
``` [5](#0-4) 

Searching the entire EVM source tree for `withdraw`, `withdrawETH`, `withdrawNative`, and `nativeFee` confirms there is no function that transfers accumulated ETH out of the contract to any party (admin, relayer, or user). [6](#0-5) 

---

### Impact Explanation

`nativeFee` is the ETH component of the bridge fee, paid by the initiating user on the EVM side to compensate relayers. Because the contract has no mechanism to distribute or withdraw this ETH, every unit of `nativeFee` paid across every `initTransfer` and `initTransfer1155` call is permanently frozen in the contract. This constitutes a continuous, irreversible loss of user funds and constitutes fee mis-accounting: the protocol collects fees it can never disburse.

---

### Likelihood Explanation

The `nativeFee` parameter is a first-class field in the public bridge API documented in the README and emitted in `InitTransfer` events. Any user who pays a non-zero `nativeFee` — the normal case when using a relayer — triggers the loss. No special conditions, no admin involvement, and no race conditions are required. The loss occurs on every such call. [7](#0-6) 

---

### Recommendation

Add an admin-gated ETH withdrawal function, accessible only to `DEFAULT_ADMIN_ROLE`, so that accumulated `nativeFee` ETH can be swept to a designated relayer treasury:

```solidity
function withdrawNativeFees(address payable recipient, uint256 amount)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    (bool ok, ) = recipient.call{value: amount}("");
    if (!ok) revert FailedToSendEther();
}
```

Alternatively, forward the `nativeFee` directly to a designated fee recipient inside `initTransfer` rather than leaving it in the contract.

---

### Proof of Concept

1. User calls `OmniBridgeWormhole.initTransfer(tokenAddress, amount, fee, nativeFee=1e17, recipient, "")` with `msg.value = 1e17 + wormholeFee`.
2. Contract computes `extensionValue = msg.value - nativeFee = wormholeFee`.
3. `initTransferExtension` forwards only `wormholeFee` to `_wormhole.publishMessage{value: wormholeFee}(...)`.
4. The `1e17` wei (`nativeFee`) remains in the contract balance.
5. No function exists to retrieve it. Repeat for every bridge user paying a native fee — ETH accumulates and is permanently locked. [8](#0-7)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
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

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L466-478)
```text
        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
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
    }
```
