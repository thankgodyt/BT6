### Title
`nativeFee` ETH Permanently Locked in `OmniBridge` — No Withdrawal Mechanism - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer` and `initTransfer1155` in `OmniBridge.sol` are `payable` and explicitly split `msg.value` into a `nativeFee` portion and an `extensionValue` portion. Only `extensionValue` is forwarded (to Wormhole in `OmniBridgeWormhole`). The `nativeFee` ETH is retained in the contract with no disbursement path and no withdrawal function anywhere in the contract. Every user who calls either function with `nativeFee > 0` permanently loses that ETH.

---

### Finding Description

In `initTransfer`, `msg.value` is partitioned as follows:

- For ERC-20 tokens: `extensionValue = msg.value - nativeFee`
- For native ETH: `extensionValue = msg.value - amount - nativeFee` [1](#0-0) 

Only `extensionValue` is passed to `initTransferExtension`: [2](#0-1) 

In `OmniBridgeWormhole.initTransferExtension`, only `value` (i.e., `extensionValue`) is forwarded to Wormhole: [3](#0-2) 

The `nativeFee` ETH is never forwarded to Wormhole, never sent to a relayer, and never refunded to the caller. The same pattern applies to `initTransfer1155`: [4](#0-3) 

A search across all EVM Solidity files confirms there is no `withdraw`, `rescue`, or `sweep` function anywhere in the contract suite. The only ETH-outflow path is `finTransfer` sending `payload.amount` to a recipient for native-ETH bridge transfers — this is unrelated to accumulated `nativeFee` balances. The contract does have a bare `receive()` that accepts ETH, but no corresponding send path for the `nativeFee` pool: [5](#0-4) 

---

### Impact Explanation

Every EVM bridge user who calls `initTransfer` or `initTransfer1155` with a non-zero `nativeFee` permanently loses that ETH. The `nativeFee` parameter is part of the documented public API (listed in the README's EVM API section) and is expected to be non-zero when a relayer fee in native ETH is required. The ETH accumulates in the `OmniBridge` contract address with no recovery path — not for the user, not for the relayer, and not for the admin. This constitutes a direct, permanent loss of user funds on every such call.

---

### Likelihood Explanation

The `nativeFee` parameter is a first-class field in the public `initTransfer` interface and is emitted in the `InitTransfer` event. Any user following the documented API who supplies a non-zero `nativeFee` (e.g., to incentivize a relayer) triggers the loss. No special permissions or attacker coordination are required — a normal unprivileged bridge user calling the public function is sufficient.

---

### Recommendation

Add a privileged withdrawal function (e.g., `DEFAULT_ADMIN_ROLE`-gated) that allows accumulated native ETH fees to be swept to a designated fee recipient or relayer treasury:

```solidity
function withdrawNativeFees(address payable recipient, uint256 amount)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
{
    (bool success, ) = recipient.call{value: amount}("");
    if (!success) revert FailedToSendEther();
}
```

Alternatively, if `nativeFee` is not intended to be collected on the EVM side, enforce `nativeFee == 0` in `initTransfer` and `initTransfer1155` and revert otherwise, preventing users from accidentally locking ETH.

---

### Proof of Concept

1. User calls `initTransfer(usdcAddress, 1000e6, 10e6, 0.01 ether, "alice.near", "")` sending `msg.value = 0.01 ether (nativeFee) + wormholeFee`.
2. Inside `initTransfer`: `extensionValue = msg.value - 0.01 ether`. Only `extensionValue` is passed to `initTransferExtension`.
3. `OmniBridgeWormhole.initTransferExtension` calls `_wormhole.publishMessage{value: extensionValue}(...)` — the Wormhole fee is consumed.
4. The `0.01 ether` `nativeFee` remains in `OmniBridge`'s balance.
5. No function exists to retrieve it. The ETH is permanently locked. [6](#0-5) [7](#0-6)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
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
