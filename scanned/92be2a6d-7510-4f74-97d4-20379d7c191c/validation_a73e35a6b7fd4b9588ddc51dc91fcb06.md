### Title
`nativeFee` ETH Permanently Locked in `OmniBridge` With No Withdrawal Mechanism - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
Every call to `initTransfer` or `initTransfer1155` that includes a non-zero `nativeFee` deposits ETH into the `OmniBridge` contract that can never be recovered. The contract also exposes a bare `receive()` function. No sweep or admin-withdrawal function exists anywhere in the contract or its Wormhole extension.

### Finding Description

In `OmniBridge.initTransfer`, the caller sends `msg.value` covering both the bridged `amount` (for native ETH) and the `nativeFee`. The code computes `extensionValue` by subtracting both:

```
extensionValue = msg.value - amount - nativeFee   // native ETH path
extensionValue = msg.value - nativeFee             // ERC-20 path
``` [1](#0-0) 

`extensionValue` is forwarded to `initTransferExtension`. In `OmniBridgeWormhole`, that value is forwarded to `_wormhole.publishMessage` as the Wormhole message fee:

```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [2](#0-1) 

The `nativeFee` portion is **never forwarded anywhere** — it stays in the contract. On the NEAR side, the relayer is compensated by minting wrapped native tokens (e.g., wETH), so the EVM-side ETH is simply abandoned in the contract.

Additionally, the contract exposes:

```solidity
receive() external payable {}
``` [3](#0-2) 

which allows anyone to send ETH directly to the contract. Neither `OmniBridge` nor `OmniBridgeWormhole` contains any `withdraw`, `sweep`, or admin-rescue function for native ETH. [4](#0-3) 

### Impact Explanation

Every `initTransfer` / `initTransfer1155` call with `nativeFee > 0` permanently locks that ETH in the contract. Over the lifetime of the bridge — which processes high-volume cross-chain transfers — the accumulated ETH becomes substantial. There is no admin path, no upgrade path that rescues it, and no on-chain mechanism to redirect it. This constitutes a permanent, irreversible loss of user-paid funds held by the protocol.

### Likelihood Explanation

`nativeFee` is a first-class parameter of the public `initTransfer` interface and is expected to be non-zero in normal bridge operation (it is the relayer incentive on the NEAR side). Every ordinary bridge user who pays a `nativeFee` contributes to the locked balance. The accumulation is continuous and automatic. [5](#0-4) 

### Recommendation

Add an admin-only ETH withdrawal function, for example:

```solidity
function withdrawNativeFees(address payable recipient, uint256 amount)
    external onlyRole(DEFAULT_ADMIN_ROLE)
{
    (bool ok, ) = recipient.call{value: amount}("");
    require(ok, "ETH transfer failed");
}
```

Alternatively, forward the `nativeFee` directly to a designated fee-recipient address at the time of `initTransfer` rather than retaining it in the contract.

### Proof of Concept

1. User calls `initTransfer(erc20Token, 1e18, 0, 1e16, "near:alice.near", "")` sending `msg.value = 1e16` (the `nativeFee`).
2. `extensionValue = 1e16 - 1e16 = 0`; Wormhole receives 0 ETH for the message fee (or the user must send extra for Wormhole separately).
3. The `1e16` wei `nativeFee` remains in `OmniBridge`'s balance.
4. On NEAR, the relayer is minted `1e16` wETH — the EVM-side ETH is never moved.
5. After N such transactions, `N × nativeFee` ETH is permanently locked with no recovery path. [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-380)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L386-413)
```text
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
