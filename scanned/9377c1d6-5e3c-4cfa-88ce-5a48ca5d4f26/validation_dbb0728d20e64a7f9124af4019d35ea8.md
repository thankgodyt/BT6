### Title
`nativeFee` ETH Permanently Locked in `OmniBridge` Contract on EVM — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

When a user calls `initTransfer` on the EVM `OmniBridge` contract with a non-zero `nativeFee`, the ETH corresponding to that fee is subtracted from `msg.value` to compute `extensionValue`, but is never forwarded anywhere. It accumulates in the contract with no withdrawal or recovery mechanism, causing permanent loss of user funds.

---

### Finding Description

In `OmniBridge.sol`, `initTransfer` is `payable` and accepts a `nativeFee` parameter intended to compensate relayers. The function computes `extensionValue` by subtracting `nativeFee` (and `amount` for ETH transfers) from `msg.value`:

```solidity
// OmniBridge.sol L387-L393
if (tokenAddress == address(0)) {
    if (fee != 0) { revert InvalidFee(); }
    extensionValue = msg.value - amount - nativeFee;
} else {
    extensionValue = msg.value - nativeFee;
    // ERC20 pull...
}
``` [1](#0-0) 

Only `extensionValue` is passed to `initTransferExtension`. In `OmniBridgeWormhole.sol`, that extension forwards exactly `value` (i.e., `extensionValue`) to Wormhole:

```solidity
// OmniBridgeWormhole.sol L143
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [2](#0-1) 

The `nativeFee` portion of `msg.value` is never forwarded to Wormhole, never paid to any relayer address, and never refunded. There is no `withdraw`, `receive()`, or fee-sweep function anywhere in the contract that could recover this ETH.

The base `initTransferExtension` in `OmniBridge.sol` reverts if `value != 0`, meaning the only deployed variant that accepts non-zero `extensionValue` is `OmniBridgeWormhole`. In both variants, `nativeFee` ETH is silently retained by the contract. [3](#0-2) 

---

### Impact Explanation

Every call to `initTransfer` with `nativeFee > 0` permanently locks that ETH in the `OmniBridge` contract. There is no admin sweep, no relayer payout path on the EVM side, and no `receive()` fallback that could drain it. Over time, as users set non-zero `nativeFee` values to attract relayers, the locked ETH accumulates and is irrecoverable. This constitutes direct, permanent loss of user funds — fee mis-accounting that changes user balances.

---

### Likelihood Explanation

The `nativeFee` parameter exists precisely to incentivize relayers. Any user who wants their EVM→NEAR transfer processed promptly will set `nativeFee > 0`. The UI/SDK is expected to suggest a non-zero value. This is a normal, expected usage path — not an edge case — making the likelihood high.

---

### Recommendation

The ETH corresponding to `nativeFee` must be explicitly routed. Two options:

1. **Forward `nativeFee` to a designated fee recipient or relayer vault** at the time of `initTransfer`, so it is not retained by the bridge contract.
2. **Revert if `msg.value != extensionValue + amount`** (for ETH transfers) or `msg.value != extensionValue + nativeFee` (for ERC20 transfers), ensuring no unaccounted ETH enters the contract.

Additionally, add a guarded `withdrawFees` function as a safety net for any ETH that accumulates due to edge cases.

---

### Proof of Concept

1. User calls `initTransfer(address(0), 1 ether, 0, 0.01 ether, "recipient.near", "")` sending `msg.value = 1.01 ether`.
2. `extensionValue = 1.01 ether - 1 ether - 0.01 ether = 0`.
3. `initTransferExtension` is called with `value = 0`; Wormhole receives 0 ETH.
4. The `0.01 ether` (`nativeFee`) remains in the `OmniBridge` contract.
5. No function exists to recover it. The ETH is permanently locked. [4](#0-3)

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
