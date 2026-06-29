### Title
Excess `msg.value` Permanently Lost in `OmniBridgeWormhole` Due to Missing Exact-Value Validation — (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

---

### Summary
`OmniBridgeWormhole` overrides `finTransferExtension` and `initTransferExtension` to forward ETH to the Wormhole `publishMessage` call. Neither override validates that the forwarded value equals exactly `_wormhole.messageFee()`. Any caller who sends excess ETH permanently loses it: the real Wormhole core contract accepts `msg.value >= messageFee()` and does not refund the surplus, and `OmniBridgeWormhole` has no ETH-rescue mechanism.

---

### Finding Description

**`finTransferExtension`** (called from the `payable` `finTransfer`):

```solidity
// OmniBridgeWormhole.sol line 109
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
```

The entire `msg.value` is forwarded to Wormhole. There is no check that `msg.value == _wormhole.messageFee()`. [1](#0-0) 

**`initTransferExtension`** (called from the `payable` `initTransfer`):

```solidity
// OmniBridgeWormhole.sol line 143
_wormhole.publishMessage{value: value}(
    wormholeNonce,
    payload,
    _consistencyLevel
);
```

Here `value` is `extensionValue`, computed in the base contract as:
- ERC-20 path: `msg.value - nativeFee`
- Native-ETH path (`tokenAddress == address(0)`): `msg.value - amount - nativeFee` [2](#0-1) 

Neither path validates that `extensionValue == _wormhole.messageFee()`. [3](#0-2) 

The base `OmniBridge.initTransferExtension` protects against excess by reverting when `value != 0`, but `OmniBridgeWormhole` overrides that guard entirely. [4](#0-3) 

The test suite enforces the exact fee only through the mock Wormhole (`require(msg.value == this.messageFee())`), which is stricter than the real Wormhole core contract. [5](#0-4) 

---

### Impact Explanation

Any unprivileged user calling `initTransfer` on `OmniBridgeWormhole` who sends `msg.value` even one wei above `nativeFee + messageFee()` (ERC-20 case) or `amount + nativeFee + messageFee()` (native-ETH case) permanently loses the surplus. The real Wormhole core contract on all supported EVM chains accepts `msg.value >= messageFee()` and retains the full amount; there is no refund path. `OmniBridgeWormhole` contains no `withdraw`, `rescue`, or `receive`/`fallback` function that could recover ETH held in the contract or forwarded to Wormhole. The bridged token transfer completes normally, so the user has no indication that ETH was lost until they inspect their balance.

---

### Likelihood Explanation

`initTransfer` is the primary user-facing entry point for cross-chain transfers on EVM chains. The required `msg.value` is `nativeFee + _wormhole.messageFee()`, where `messageFee()` is a dynamic value that can change via Wormhole governance. A user relying on a cached fee quote, a frontend rounding up for safety, or a wallet that adds a small buffer will silently lose the excess. This is a realistic, low-friction mistake with no on-chain warning.

---

### Recommendation

In `OmniBridgeWormhole`, validate the forwarded value against `_wormhole.messageFee()` before calling `publishMessage`:

```solidity
// finTransferExtension
uint256 fee = _wormhole.messageFee();
require(msg.value == fee, "InvalidWormholeFee");
_wormhole.publishMessage{value: fee}(...);

// initTransferExtension
uint256 fee = _wormhole.messageFee();
require(value == fee, "InvalidWormholeFee");
_wormhole.publishMessage{value: fee}(...);
```

This mirrors the fix recommended in the external report: add an exact-equality check so that any excess causes an immediate revert rather than a silent loss.

---

### Proof of Concept

1. Wormhole `messageFee()` is `10_000 wei` (as in the test setup). [6](#0-5) 
2. User calls `OmniBridgeWormhole.initTransfer(tokenAddress, amount, fee, nativeFee, recipient, message, {value: nativeFee + 10_001})` — one wei over the Wormhole fee.
3. Base contract computes `extensionValue = msg.value - nativeFee = 10_001`. [7](#0-6) 
4. `OmniBridgeWormhole.initTransferExtension` calls `_wormhole.publishMessage{value: 10_001}(...)`. [8](#0-7) 
5. The real Wormhole core contract accepts the call (`10_001 >= 10_000`) and retains all `10_001 wei`.
6. The transfer event is emitted, the bridge proceeds normally, and the user's extra `1 wei` is permanently lost with no revert or log.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L108-113)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L142-148)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

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

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L12-15)
```text
    ) external payable returns (uint64) {
        require(msg.value == this.messageFee(), "invalid fee");
        emit MessagePublished(nonce, payload, consistencyLevel);
        return 0;
```

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L18-20)
```text
    function messageFee() external pure returns (uint256) {
        return 10000;
    }
```
