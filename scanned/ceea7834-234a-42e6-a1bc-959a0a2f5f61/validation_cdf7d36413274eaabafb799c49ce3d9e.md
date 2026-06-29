### Title
Native ETH `nativeFee` Permanently Locked in `OmniBridge` Contract — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

Every EVM user who pays a non-zero `nativeFee` in ETH when calling `initTransfer` or `initTransfer1155` causes that ETH to accumulate permanently inside `OmniBridge.sol`. There is no withdrawal, sweep, or relayer-payout function for native ETH in the contract, so the funds are irrecoverable.

### Finding Description

`initTransfer` is `payable` and splits `msg.value` into two parts:

- `extensionValue` — forwarded to `initTransferExtension` (used by `OmniBridgeWormhole` to pay Wormhole's `publishMessage` fee).
- `nativeFee` — the remainder that is **kept in the contract** and never forwarded anywhere. [1](#0-0) 

For ERC-20 tokens:
```
extensionValue = msg.value - nativeFee;   // nativeFee stays in contract
```

For native ETH token transfers:
```
extensionValue = msg.value - amount - nativeFee;  // nativeFee stays in contract
``` [2](#0-1) 

`initTransfer1155` has the same pattern: [3](#0-2) 

In `OmniBridgeWormhole`, `initTransferExtension` only spends `value` (the `extensionValue`) on Wormhole — the `nativeFee` portion is never touched: [4](#0-3) 

`OmniBridge.sol` declares no `receive()`, no `fallback()`, and no ETH-withdrawal function. The base `initTransferExtension` reverts if `value != 0`, confirming the design intent is that `extensionValue` is consumed — but `nativeFee` is silently retained with no exit path. [5](#0-4) 

### Impact Explanation

Every EVM→NEAR transfer where the user specifies `nativeFee > 0` permanently locks that ETH in the bridge contract. The relayer never receives the ETH fee it is owed. The user's ETH is irrecoverable without an admin contract upgrade. This is a permanent freezing of user funds — matching the Critical impact tier.

### Likelihood Explanation

High. The `nativeFee` parameter is a first-class, documented feature of the bridge API (README explicitly shows it as a transfer parameter). Any user following the documented flow and paying a native fee triggers the loss. It affects every EVM chain deployment (`OmniBridgeWormhole` on Ethereum, Arbitrum, Base, BNB, Polygon).

### Recommendation

Add a mechanism to pay the accumulated `nativeFee` ETH to the relayer/fee recipient. The simplest fix mirrors the NEAR-side `send_fee_internal` pattern: forward the `nativeFee` ETH directly to the designated fee recipient at `initTransfer` time, or store it keyed by nonce and allow the relayer to claim it after proof submission. At minimum, add an admin ETH-sweep function so funds are not permanently frozen.

### Proof of Concept

1. User calls `OmniBridgeWormhole.initTransfer(tokenAddress, amount, fee=0, nativeFee=1 ether, recipient, "")` with `msg.value = 1 ether`.
2. Inside `initTransfer`: `extensionValue = 1 ether - 1 ether = 0`. `nativeFee = 1 ether` stays in the contract.
3. `initTransferExtension` is called with `value = 0`; Wormhole `publishMessage{value: 0}` succeeds (zero Wormhole fee scenario) or reverts (non-zero Wormhole fee scenario — but the ETH is still not returned to the user).
4. The 1 ETH `nativeFee` sits in `OmniBridge`'s balance. No function exists to move it. The relayer processes the transfer on NEAR and receives no ETH compensation. [6](#0-5) [7](#0-6)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L466-466)
```text
        uint256 extensionValue = msg.value - nativeFee;
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
