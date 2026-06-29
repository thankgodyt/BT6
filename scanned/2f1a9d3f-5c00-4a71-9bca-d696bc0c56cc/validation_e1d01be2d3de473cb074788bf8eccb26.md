### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` uses `safeTransferFrom` to pull ERC20 tokens from the caller but unconditionally uses the caller-supplied `amount` parameter in all downstream accounting — the `InitTransfer` event and the Wormhole cross-chain message. For fee-on-transfer tokens (e.g., USDT with a non-zero fee rate), the bridge receives fewer tokens than `amount`, yet the cross-chain message claims the full `amount` was locked. NEAR then mints/credits the full `amount` to the recipient, creating a permanent escrow deficit that can be exploited to drain the bridge.

---

### Finding Description

In `initTransfer`, the standard ERC20 lock path is:

```solidity
// OmniBridge.sol lines 406-412
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount          // caller-controlled input
    );
}
``` [1](#0-0) 

Immediately after, `initTransferExtension` is called with the original `amount` parameter, and the `InitTransfer` event is emitted:

```solidity
// OmniBridge.sol lines 415-436
initTransferExtension(
    msg.sender, tokenAddress, currentOriginNonce,
    amount,   // <-- not the actual received balance
    fee, nativeFee, recipient, message, extensionValue
);

emit BridgeTypes.InitTransfer(
    msg.sender, tokenAddress, currentOriginNonce,
    amount,   // <-- not the actual received balance
    fee, nativeFee, recipient, message
);
``` [2](#0-1) 

In `OmniBridgeWormhole`, `initTransferExtension` publishes a Wormhole VAA containing the unchecked `amount`:

```solidity
// OmniBridgeWormhole.sol lines 129-141
bytes memory payload = bytes.concat(
    ...
    Borsh.encodeUint128(amount),   // claimed locked amount
    ...
);
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [3](#0-2) 

No balance check is performed before or after the `safeTransferFrom` call to determine the actual amount received. The contract never computes `balanceAfter - balanceBefore`.

A secondary affected path is the `customMinters` branch (lines 394–403), where `safeTransferFrom` sends `amount` to the custom minter and then `burn(tokenAddress, amount)` is called. If the token deducted a fee, the custom minter received less than `amount`, making the subsequent `burn` call operate on an inflated figure. [4](#0-3) 

---

### Impact Explanation

**Critical — Escrow mis-accounting / unauthorized minting of bridged funds.**

For every `initTransfer` call with a fee-on-transfer token:

- EVM bridge holds: `amount - token_transfer_fee`
- NEAR credits to recipient: `amount` (full, per the Wormhole message)

The difference (`token_transfer_fee`) is minted on NEAR without a corresponding locked balance on EVM. When those tokens are bridged back, `finTransfer` attempts to release `amount` tokens from the EVM escrow, but the escrow is short. Repeated exploitation drains the EVM bridge's reserves, causing legitimate users' withdrawals to fail (permanent freezing of bridged funds) and allowing the attacker to extract more value from NEAR than was ever deposited on EVM.

---

### Likelihood Explanation

**Medium-High.** USDT's fee mechanism is currently set to 0% but is a well-known, documented risk. Any token with a non-zero transfer fee that is registered with the bridge (either as a standard ERC20 or via `addCustomToken`) immediately triggers this path. The entry point (`initTransfer`) is public, unpermissioned, and callable by any token holder. No admin compromise or special role is required.

---

### Recommendation

Measure the actual received amount by checking the contract's balance before and after the `safeTransferFrom` call, and use the delta for all downstream accounting:

```solidity
} else {
    uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
    IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
    uint256 balanceAfter = IERC20(tokenAddress).balanceOf(address(this));
    uint128 actualReceived = uint128(balanceAfter - balanceBefore);
    // use actualReceived instead of amount in all subsequent calls
    amount = actualReceived;
}
```

Apply the same pattern to the `customMinters` branch: measure what the custom minter actually received before calling `burn`.

---

### Proof of Concept

1. Deploy or register a fee-on-transfer ERC20 token (e.g., a USDT fork with a 1% transfer fee) with the `OmniBridgeWormhole` contract as a standard (non-bridge, non-custom-minter) token.
2. Call `initTransfer(tokenAddress, 1000e6, 0, nativeFee, nearRecipient, "")` with `amount = 1000e6`.
3. The `safeTransferFrom` transfers 1000e6 from the caller, but the bridge receives only 990e6 (after 1% fee).
4. The Wormhole VAA is published with `amount = 1000e6`.
5. The NEAR `omni-bridge` processes the VAA and mints 1000e6 tokens to `nearRecipient`.
6. The attacker bridges 1000e6 tokens back from NEAR to EVM via `finTransfer`.
7. `finTransfer` calls `IERC20(tokenAddress).safeTransfer(recipient, 1000e6)`, but the bridge only holds 990e6 — the transfer fails for the last legitimate user, or the attacker has extracted 10e6 more value than deposited, with the deficit accumulating across repeated calls. [5](#0-4) [6](#0-5)

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
