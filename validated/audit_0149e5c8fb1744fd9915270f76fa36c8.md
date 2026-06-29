### Title
`nativeFee` ETH Permanently Locked in `OmniBridge` — No Withdrawal Mechanism - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary
`OmniBridge.sol` accepts ETH via a bare `receive()` function and via `payable` entry points (`initTransfer`, `initTransfer1155`, `deployToken`, `logMetadata`, `logMetadata1155`, `finTransfer`). Every call to `initTransfer` / `initTransfer1155` that includes a non-zero `nativeFee` permanently locks that ETH inside the contract. No `withdraw`, `rescue`, or admin-recovery function exists anywhere in the contract or its inheritance chain.

---

### Finding Description

`OmniBridge.initTransfer` computes `extensionValue` by subtracting both `amount` and `nativeFee` from `msg.value`:

```solidity
// OmniBridge.sol line 391
extensionValue = msg.value - amount - nativeFee;   // native-ETH path
// line 393
extensionValue = msg.value - nativeFee;            // ERC-20 path
``` [1](#0-0) 

Only `extensionValue` is forwarded to `initTransferExtension`. In `OmniBridgeWormhole`, that value is forwarded to `_wormhole.publishMessage{value: value}(...)`:

```solidity
// OmniBridgeWormhole.sol line 143
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [2](#0-1) 

The `nativeFee` portion is never forwarded, never sent to a relayer, and never emitted as a claimable balance. It simply accumulates in the contract's ETH balance.

Additionally, the contract exposes a bare `receive()`:

```solidity
receive() external payable {}
``` [3](#0-2) 

There is no `withdraw`, `rescueETH`, or any admin function that moves ETH out of the contract. A full search of `OmniBridge.sol` and `OmniBridgeWormhole.sol` confirms zero ETH-recovery paths. [4](#0-3) 

---

### Impact Explanation

Every `initTransfer` / `initTransfer1155` call with `nativeFee > 0` permanently destroys that ETH. Because `nativeFee` is the mechanism by which users compensate relayers for EVM-side gas, this fee is expected to be non-zero in normal bridge operation. The ETH is not lost due to an edge-case mistake; it is lost on every standard bridge transfer. This constitutes permanent, protocol-level fee mis-accounting and loss of user funds with no recovery path.

**Impact: Critical** — permanent loss of user-paid ETH on every bridge transfer.

---

### Likelihood Explanation

Any unprivileged user calling `initTransfer` or `initTransfer1155` with `nativeFee > 0` (the normal operating case) triggers the loss. No special conditions, admin access, or error is required. The loss is automatic and continuous across all bridge usage.

**Likelihood: High** — triggered by normal, expected bridge usage.

---

### Recommendation

1. Track accumulated `nativeFee` in a storage variable (e.g., per-relayer or as a global claimable pool) and add a `withdrawNativeFees(address recipient)` function restricted to `DEFAULT_ADMIN_ROLE` or a designated fee-recipient role.
2. Alternatively, forward `nativeFee` directly to a designated `feeRecipient` address inside `initTransfer` at the time of the call.
3. Remove or revert-guard the bare `receive()` function if the contract is not intended to accept unsolicited ETH beyond what `initTransfer` deposits.

---

### Proof of Concept

1. Deploy `OmniBridgeWormhole` (or use the base `OmniBridge` with a stub extension).
2. Call `initTransfer(erc20Token, 1e18, 0, 0.01 ether, "recipient.near", "")` with `msg.value = 0.01 ether` (the `nativeFee`).
3. Observe: `extensionValue = 0.01 ether - 0.01 ether = 0`; `_wormhole.publishMessage{value: 0}(...)` is called; the contract's ETH balance increases by `0.01 ether`.
4. Repeat for any number of transfers. The contract ETH balance grows monotonically.
5. Confirm: no function in `OmniBridge.sol` or `OmniBridgeWormhole.sol` can move this ETH out. [5](#0-4) [2](#0-1)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-598)
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

    uint256[49] private __gap;
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
