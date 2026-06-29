### Title
`nativeFee` ETH Permanently Locked in `OmniBridgeWormhole` with No Withdrawal or Distribution Mechanism — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

When a user calls `initTransfer` or `initTransfer1155` on `OmniBridgeWormhole` with `nativeFee > 0`, the ETH corresponding to `nativeFee` is silently retained in the contract. Only the `extensionValue` portion (`msg.value − nativeFee`) is forwarded to the Wormhole core bridge. There is no `receive()`, `fallback()`, or withdrawal function in either `OmniBridge` or `OmniBridgeWormhole` that can recover or distribute this ETH. The `nativeFee` ETH is permanently locked.

---

### Finding Description

In `OmniBridge.initTransfer`, `msg.value` is partitioned as follows:

```
extensionValue = msg.value − nativeFee          // for ERC-20 tokens
extensionValue = msg.value − amount − nativeFee // for native ETH (tokenAddress == 0)
``` [1](#0-0) 

`extensionValue` is then passed to `initTransferExtension`, which in `OmniBridgeWormhole` forwards it to Wormhole:

```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [2](#0-1) 

The Wormhole core bridge (and the in-repo `TestWormhole`) enforces an **exact** fee match (`msg.value == messageFee()`), so `extensionValue` must equal exactly `messageFee()`. This means the user must send:

```
msg.value = nativeFee + messageFee()   (ERC-20)
msg.value = amount + nativeFee + messageFee()  (native ETH)
```

The `nativeFee` portion is never forwarded anywhere. It accumulates in the `OmniBridgeWormhole` contract. Neither `OmniBridge` nor `OmniBridgeWormhole` defines a `receive()`, `fallback()`, or any ETH-withdrawal function, so this ETH has no exit path. [3](#0-2) 

The same pattern applies to `initTransfer1155`: [4](#0-3) 

On the NEAR side, the relayer is compensated in **NEAR tokens** (yoctoNEAR) drawn from the user's storage balance — not in ETH. The EVM-side `nativeFee` ETH therefore has no legitimate recipient and no distribution path. [5](#0-4) 

---

### Impact Explanation

Any user who calls `initTransfer` or `initTransfer1155` with `nativeFee > 0` permanently loses that ETH. The funds are locked inside `OmniBridgeWormhole` with no recovery mechanism. Over time, as multiple users set non-zero `nativeFee` values (e.g., to incentivize relayers, following the same mental model as the NEAR-side `native_token_fee`), the cumulative ETH locked grows and is irrecoverable without a contract upgrade.

This satisfies the allowed critical impact: **permanent loss of bridged/user funds on an EVM chain**.

---

### Likelihood Explanation

The `nativeFee` parameter is a first-class field in the `InitTransfer` event and in the cross-chain message payload. Users who observe the NEAR-side `native_token_fee` mechanic (where a non-zero value incentivises relayers) will naturally set a non-zero `nativeFee` on the EVM side for the same reason. The contract imposes no upper bound and no enforcement of `nativeFee == 0`. Any unprivileged bridge user can trigger this loss by simply supplying a non-zero `nativeFee` argument. [6](#0-5) 

---

### Recommendation

Choose one of:

1. **Enforce `nativeFee == 0` on EVM.** Add `if (nativeFee != 0) revert InvalidFee();` at the top of `initTransfer` and `initTransfer1155`, since relayer compensation on EVM-originated transfers is handled entirely in NEAR tokens on the NEAR side.

2. **Refund `nativeFee` to `msg.sender`.** After the Wormhole `publishMessage` call succeeds, return the `nativeFee` ETH to the caller.

3. **Route `nativeFee` to a designated relayer address.** If ETH-denominated relayer fees are intentional, add an explicit transfer of `nativeFee` to the relayer or a fee-collector address within `initTransferExtension`.

---

### Proof of Concept

1. Wormhole `messageFee()` = 10 000 wei (as configured in `TestWormhole`).
2. User calls:
   ```solidity
   OmniBridgeWormhole.initTransfer(
       erc20Token,   // tokenAddress
       1000,         // amount
       0,            // fee
       1 ether,      // nativeFee  ← attacker-controlled, non-zero
       "alice.near", // recipient
       "",           // message
       { value: 1 ether + 10_000 }  // nativeFee + messageFee
   );
   ```
3. Inside `initTransfer`: `extensionValue = (1 ether + 10_000) − 1 ether = 10_000`.
4. `initTransferExtension` calls `_wormhole.publishMessage{value: 10_000}(...)` — succeeds (exact fee).
5. `1 ether` remains in `OmniBridgeWormhole`. No function exists to withdraw it.
6. The `InitTransfer` event is emitted; the NEAR relayer is paid in NEAR tokens. The 1 ETH is permanently locked. [3](#0-2) [7](#0-6)

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
