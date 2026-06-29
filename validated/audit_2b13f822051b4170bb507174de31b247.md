Looking at the actual code to verify each claim in the report.

Audit Report

## Title
`nativeFee` ETH Permanently Locked With No Withdrawal Mechanism - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`OmniBridge.initTransfer` and `initTransfer1155` accept `nativeFee` as part of `msg.value` but only forward `extensionValue` (i.e., `msg.value - nativeFee`) to `initTransferExtension`. In `OmniBridgeWormhole`, only `extensionValue` is forwarded to `_wormhole.publishMessage{value: value}(...)`. The ETH corresponding to `nativeFee` accumulates in the contract indefinitely. No `withdraw`, `rescueETH`, or any admin-callable ETH-recovery function exists anywhere in the contract or its inheritance chain, making the locked ETH irrecoverable under the current implementation.

## Finding Description
In `OmniBridge.initTransfer`, `extensionValue` is computed by subtracting `nativeFee` from `msg.value`:

- ERC-20 path: `extensionValue = msg.value - nativeFee` [1](#0-0) 
- Native ETH path: `extensionValue = msg.value - amount - nativeFee` [2](#0-1) 

Only `extensionValue` is passed to `initTransferExtension`. [3](#0-2) 

In `OmniBridgeWormhole.initTransferExtension`, only `value` (i.e., `extensionValue`) is forwarded to Wormhole: `_wormhole.publishMessage{value: value}(...)`. [4](#0-3) 

The `nativeFee` amount is encoded into the Wormhole payload [5](#0-4)  and communicated to NEAR, but the corresponding ETH remains in the contract with no disbursement path. The same pattern applies to `initTransfer1155`. [6](#0-5) 

The contract exposes a bare `receive()` with no accounting, and a full search of both contracts confirms zero ETH-recovery functions (`withdraw`, `rescueETH`, or equivalent). [7](#0-6) 

The `TestWormhole` stub confirms the expected call pattern: `publishMessage` requires `msg.value == messageFee()`, meaning the Wormhole fee is exactly `extensionValue`, and `nativeFee` is structurally excluded from any outgoing ETH flow. [8](#0-7) 

## Impact Explanation
Every `initTransfer` / `initTransfer1155` call with `nativeFee > 0` permanently locks that ETH in the contract. Because `nativeFee` is the mechanism by which users compensate relayers for EVM-side gas, it is expected to be non-zero in normal bridge operation. The ETH is not recoverable under the current implementation: no function in `OmniBridge.sol` or `OmniBridgeWormhole.sol` moves ETH out of the contract to any relayer, fee recipient, or admin address. This constitutes **fee mis-accounting that permanently changes user and protocol balances**, matching the Critical allowed impact: *"fee mis-accounting … that changes user or protocol balances."*

## Likelihood Explanation
Any unprivileged user calling `initTransfer` or `initTransfer1155` with `nativeFee > 0` triggers the loss. No special conditions, admin access, or error state is required. The loss is automatic and continuous across all standard bridge usage where relayer compensation is expected.

## Recommendation
1. Forward `nativeFee` directly to a designated `feeRecipient` address inside `initTransfer` at call time (e.g., `payable(feeRecipient).transfer(nativeFee)`), or
2. Track accumulated `nativeFee` in a per-relayer or global claimable storage variable and add a `withdrawNativeFees(address recipient)` function restricted to `DEFAULT_ADMIN_ROLE` or a designated fee-recipient role, or
3. If `nativeFee` is intended solely as an informational field for the NEAR side (with no EVM-side ETH movement), enforce `nativeFee == 0` or require `msg.value` to equal only `amount + extensionValue`, reverting otherwise.

## Proof of Concept
1. Deploy `OmniBridgeWormhole` with `TestWormhole` (messageFee = 10000 wei).
2. Call `initTransfer(erc20Token, 1e18, 0, 0.01 ether, "recipient.near", "")` with `msg.value = 0.01 ether + 10000` (nativeFee + Wormhole fee).
3. Observe: `extensionValue = msg.value - nativeFee = 10000`; `_wormhole.publishMessage{value: 10000}(...)` succeeds; contract ETH balance increases by `0.01 ether`.
4. Repeat for any number of transfers. Contract ETH balance grows monotonically.
5. Confirm: no function in `OmniBridge.sol` or `OmniBridgeWormhole.sol` can move this ETH out. [9](#0-8)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L391-391)
```text
            extensionValue = msg.value - amount - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L392-393)
```text
        } else {
            extensionValue = msg.value - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L415-425)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L466-466)
```text
        uint256 extensionValue = msg.value - nativeFee;
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L138-138)
```text
            Borsh.encodeUint128(nativeFee),
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L143-147)
```text
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L13-13)
```text
        require(msg.value == this.messageFee(), "invalid fee");
```
