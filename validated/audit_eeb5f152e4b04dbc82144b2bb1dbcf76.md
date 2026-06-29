The code confirms the claim. Let me verify the key facts:

**`OmniBridge.finTransfer`** (lines 317–322 and 357):
- Sends `payload.amount` wei to `payload.recipient` when `tokenAddress == address(0)` [1](#0-0) 
- Then calls `finTransferExtension(payload)` [2](#0-1) 

**`OmniBridgeWormhole.finTransferExtension`** (lines 109):
- Forwards the full `msg.value` to Wormhole, not the residual after the recipient payment [3](#0-2) 

**`OmniBridge.initTransfer`** (line 391):
- Correctly computes `extensionValue = msg.value - amount - nativeFee` before passing it to `initTransferExtension` [4](#0-3) 

The asymmetry is real and the arithmetic failure is concrete: after `payload.amount` is spent, the contract holds only `msg.value - payload.amount`, but `finTransferExtension` attempts to forward `msg.value`, causing an out-of-funds revert. The nonce is not permanently consumed (the revert rolls back `completedTransfers[payload.destinationNonce] = true`), but the source-chain ETH has no withdrawal path, making it permanently frozen.

---

Audit Report

## Title
`finTransferExtension` Forwards Full `msg.value` to Wormhole After Native ETH Has Been Sent to Recipient, Causing Permanent Revert — (`evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary
`OmniBridgeWormhole.finTransferExtension` calls `_wormhole.publishMessage{value: msg.value}(...)`, forwarding the entire original `msg.value`. However, when `payload.tokenAddress == address(0)`, the base `OmniBridge.finTransfer` has already spent `payload.amount` wei sending ETH to the recipient before `finTransferExtension` is invoked. The contract's remaining balance is only `msg.value - payload.amount`, so the Wormhole call always reverts with an out-of-funds error, permanently preventing finalization of any native ETH cross-chain transfer through the Wormhole path and freezing the locked ETH on the source chain.

## Finding Description
In `OmniBridge.finTransfer`, when `payload.tokenAddress == address(0)`, the contract sends `payload.amount` wei to the recipient:

```solidity
// OmniBridge.sol L317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

Control then passes to `finTransferExtension` (L357). In `OmniBridgeWormhole`, this is:

```solidity
// OmniBridgeWormhole.sol L109-113
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
```

`msg.value` is the total ETH attached to the transaction. After `payload.amount` has been forwarded to the recipient, the contract holds only `msg.value - payload.amount` wei. Attempting to forward `msg.value` to Wormhole will always revert when `payload.amount > 0` and the contract has no pre-existing ETH surplus.

By contrast, `initTransfer` correctly computes the residual before passing it to `initTransferExtension`:

```solidity
// OmniBridge.sol L391
extensionValue = msg.value - amount - nativeFee;
// OmniBridgeWormhole.sol L143
_wormhole.publishMessage{value: value}(...)
```

`finTransferExtension` lacks the equivalent subtraction, making the two paths asymmetric. The root cause is that `msg.value` is a transaction-level constant and does not reflect the contract's remaining balance after intermediate ETH sends.

## Impact Explanation
Every call to `finTransfer` with `payload.tokenAddress == address(0)` on `OmniBridgeWormhole` reverts. Because the entire transaction reverts, `completedTransfers[payload.destinationNonce]` is never durably set, so the nonce remains unconsumed and the call can be retried — but it will always revert. The source-chain ETH locked during `initTransfer` has no cancellation or withdrawal path in the contract, resulting in **permanent freezing of all bridged native ETH routed through `OmniBridgeWormhole`**. This matches the critical impact class: permanent freezing of bridged funds.

## Likelihood Explanation
Any unprivileged user who calls `initTransfer(address(0), ...)` on a deployed `OmniBridgeWormhole` instance triggers the freeze. No special role, key, or collusion is required. The Wormhole variant is deployed on Arbitrum and Base (where the native token is ETH), making this path reachable in production. Any relayer attempting to finalize such a transfer will encounter the revert unconditionally.

## Recommendation
In `finTransferExtension`, compute the Wormhole fee as the ETH remaining after the recipient payment, mirroring the pattern used in `initTransferExtension`:

```solidity
function finTransferExtension(
    BridgeTypes.TransferMessagePayload memory payload
) internal override {
    uint256 wormholeFee = payload.tokenAddress == address(0)
        ? msg.value - payload.amount
        : msg.value;

    bytes memory messagePayload = bytes.concat(
        bytes1(uint8(MessageType.FinTransfer)),
        bytes1(payload.originChain),
        Borsh.encodeUint64(payload.originNonce),
        bytes1(omniBridgeChainId),
        Borsh.encodeAddress(payload.tokenAddress),
        Borsh.encodeUint128(payload.amount),
        Borsh.encodeString(payload.feeRecipient)
    );
    _wormhole.publishMessage{value: wormholeFee}(
        wormholeNonce,
        messagePayload,
        _consistencyLevel
    );
    wormholeNonce++;
}
```

## Proof of Concept
1. Deploy `OmniBridgeWormhole` on Arbitrum Sepolia with a valid Wormhole address.
2. Call `initTransfer(address(0), 1 ether, 0, nativeFee, recipient, "")` with `msg.value = 1 ether + nativeFee`. ETH is locked in the contract.
3. A relayer calls `finTransfer(sig, payload)` where `payload.tokenAddress == address(0)` and `payload.amount == 1 ether`, attaching `msg.value = 1 ether + wormholeFee` (the minimum needed to cover both the recipient payment and the Wormhole fee).
4. `finTransfer` sends `1 ether` to the recipient; contract balance drops to `wormholeFee`.
5. `finTransferExtension` attempts `_wormhole.publishMessage{value: msg.value}(...)` = `{value: 1 ether + wormholeFee}` — reverts because only `wormholeFee` remains.
6. The entire transaction reverts; the source-chain ETH remains permanently locked with no withdrawal path.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L357-357)
```text
        finTransferExtension(payload);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L391-391)
```text
            extensionValue = msg.value - amount - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L109-113)
```text
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );
```
