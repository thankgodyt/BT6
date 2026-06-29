The code confirms the vulnerability. Let me verify the key facts:

1. **`OmniBridge.finTransfer`** (line 317-322): When `payload.tokenAddress == address(0)`, it sends `payload.amount` ETH to the recipient via `.call{value: payload.amount}("")`, then unconditionally calls `finTransferExtension(payload)` at line 357. [1](#0-0) [2](#0-1) 

2. **`OmniBridgeWormhole.finTransferExtension`** (line 109): Uses `msg.value` raw — not a residual — when calling `_wormhole.publishMessage`. [3](#0-2) 

3. **`initTransfer`** correctly computes `extensionValue = msg.value - amount - nativeFee` and passes it explicitly to `initTransferExtension`, which uses `value` (not `msg.value`). [4](#0-3) [5](#0-4) 

One inaccuracy in the submitted PoC: step 6 claims the nonce is permanently consumed. Since the entire transaction reverts (including the `completedTransfers[payload.destinationNonce] = true` write at line 287), the nonce is **not** permanently consumed — the transfer can be retried. However, every retry will fail for the same reason, so the practical impact (permanent freezing) is unchanged.

---

Audit Report

## Title
`OmniBridgeWormhole.finTransferExtension` Forwards Full `msg.value` to Wormhole After Native ETH Already Sent to Recipient, Causing Unconditional Revert - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary
When `finTransfer` is called with `payload.tokenAddress == address(0)`, the base contract sends `payload.amount` ETH to the recipient, reducing the contract's available balance to `msg.value - payload.amount`. `OmniBridgeWormhole.finTransferExtension` then attempts `_wormhole.publishMessage{value: msg.value}(...)`, forwarding the full original `msg.value` which exceeds the remaining balance, causing every such transaction to revert. No native ETH bridge completion on any Wormhole-connected EVM chain can ever succeed.

## Finding Description
In `OmniBridge.finTransfer` (lines 317–357), when `payload.tokenAddress == address(0)`, `payload.amount` ETH is sent to `payload.recipient` via `.call{value: payload.amount}("")`. After this call succeeds, `finTransferExtension(payload)` is invoked unconditionally. `OmniBridgeWormhole.finTransferExtension` (lines 96–116) then calls `_wormhole.publishMessage{value: msg.value}(...)`, using the original `msg.value` rather than the residual `msg.value - payload.amount`. Since `payload.amount` ETH has already left the contract, the contract holds only `msg.value - payload.amount` at that point. Forwarding `msg.value` exceeds the available balance and the EVM reverts the entire transaction — including the ETH transfer to the recipient and the nonce write — so the transfer can be retried, but every retry fails identically. The `initTransfer` path correctly avoids this by computing `extensionValue = msg.value - amount - nativeFee` and passing it as an explicit parameter to `initTransferExtension`, which uses `value` (not `msg.value`). The `finTransfer` path has no equivalent residual computation.

## Impact Explanation
Critical. Every attempt to finalize a NEAR → EVM native ETH transfer via `OmniBridgeWormhole.finTransfer` reverts unconditionally. Relayers cannot complete these transfers. Funds locked on the NEAR side for native ETH transfers can never be released on the destination chain, constituting permanent freezing of bridged ETH — a direct match for the allowed critical impact class of permanent freezing of bridged funds.

## Likelihood Explanation
High. Native ETH (`address(0)`) is explicitly supported as a bridgeable asset with a dedicated branch in `finTransfer`. Any user who initiates a NEAR → EVM native ETH transfer triggers this path. No special attacker capability is required; the bug is triggered by the normal relayer flow for any such transfer.

## Recommendation
Mirror the `initTransfer` pattern: compute the residual ETH value in `finTransfer` before calling `finTransferExtension`, and thread it through as an explicit parameter.

In `OmniBridge.finTransfer`, before calling `finTransferExtension`:
```solidity
uint256 extensionValue = (payload.tokenAddress == address(0))
    ? msg.value - payload.amount
    : msg.value;
finTransferExtension(payload, extensionValue);
```

Update `finTransferExtension` signatures in both `OmniBridge` and `OmniBridgeWormhole` to accept `uint256 value` and use it instead of `msg.value`:
```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, messagePayload, _consistencyLevel);
```

## Proof of Concept
1. Deploy `OmniBridgeWormhole` on an EVM testnet with a mock Wormhole contract that charges `wormholeFee`.
2. Call `finTransfer` with `payload.tokenAddress = address(0)`, `payload.amount = 1 ether`, sending `msg.value = 1 ether + wormholeFee`.
3. Observe: the base contract attempts `.call{value: 1 ether}("")` to the recipient — this succeeds internally.
4. `finTransferExtension` then calls `_wormhole.publishMessage{value: 1 ether + wormholeFee}(...)`, but the contract only holds `wormholeFee` ETH.
5. The EVM reverts the entire transaction; the recipient receives nothing and the nonce is not consumed.
6. Every subsequent retry with the same or any valid `msg.value` fails identically, permanently blocking finalization of the transfer.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L355-357)
```text
        }

        finTransferExtension(payload);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L387-425)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L109-113)
```text
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L143-147)
```text
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```
