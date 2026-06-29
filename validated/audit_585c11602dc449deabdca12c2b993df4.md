Audit Report

## Title
Native ETH `finTransfer` Always Reverts Due to Double-Spending of `msg.value` in Wormhole Fee Forwarding - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary
`OmniBridge.finTransfer` sends `payload.amount` ETH to the recipient before invoking `finTransferExtension`. `OmniBridgeWormhole.finTransferExtension` then attempts to forward the full original `msg.value` to Wormhole's `publishMessage`, but the contract's balance has already been reduced by `payload.amount`. This causes every native ETH (`tokenAddress == address(0)`) finalization on the Wormhole path to revert deterministically, permanently preventing release of ETH bridged from NEAR.

## Finding Description
In `OmniBridge.finTransfer`, the nonce is marked used and ETH is sent to the recipient before the extension hook fires:

```solidity
// OmniBridge.sol L317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
// ...
finTransferExtension(payload);   // L357 — called after ETH is already spent
``` [1](#0-0) [2](#0-1) 

`OmniBridgeWormhole.finTransferExtension` unconditionally forwards the full original `msg.value` to Wormhole:

```solidity
// OmniBridgeWormhole.sol L109-113
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
``` [3](#0-2) 

At the point `finTransferExtension` executes, the contract holds only `msg.value - payload.amount` ETH. Attempting to forward `msg.value` exceeds the available balance and the EVM reverts the entire transaction. The `TestWormhole` mock confirms the real Wormhole interface enforces an exact-fee check (`require(msg.value == this.messageFee(), "invalid fee")`), so even if the balance issue were resolved, forwarding `payload.amount + wormholeFee` instead of just `wormholeFee` would still revert. [4](#0-3) 

Note that `initTransfer` correctly avoids this pattern by computing `extensionValue = msg.value - amount - nativeFee` and passing only that residual to `initTransferExtension`, which then forwards `value` (not `msg.value`) to Wormhole. `finTransferExtension` lacks the equivalent accounting. [5](#0-4) [6](#0-5) 

## Impact Explanation
Every call to `finTransfer` where `payload.tokenAddress == address(0)` reverts at the Wormhole step. Because the entire transaction reverts, the nonce is never consumed, but the bug is deterministic — no call sequence can succeed. ETH that users locked or burned on NEAR expecting delivery on the EVM chain via the Wormhole path cannot be released. This constitutes permanent freezing of bridged ETH, matching the critical allowed impact: *permanent freezing of bridged funds across NEAR/EVM/Wormhole-routed flows*.

## Likelihood Explanation
No special attacker capability is required. Any relayer or user calling `finTransfer` with a valid NEAR-signed payload for a native ETH transfer triggers the revert unconditionally. The function has no access control. The failure is 100% reproducible on every such call with no edge-case dependency. [7](#0-6) 

## Recommendation
In `finTransferExtension`, forward only the Wormhole message fee, not `msg.value`. The caller of `finTransfer` for native ETH must supply `msg.value = payload.amount + wormholeFee`:

```solidity
function finTransferExtension(
    BridgeTypes.TransferMessagePayload memory payload
) internal override {
    // ...build messagePayload...
    uint256 wormholeFee = _wormhole.messageFee();
    _wormhole.publishMessage{value: wormholeFee}(
        wormholeNonce,
        messagePayload,
        _consistencyLevel
    );
    wormholeNonce++;
}
```

This mirrors the correct pattern already used in `initTransferExtension`, which receives a pre-computed `value` parameter stripped of the token amount. [8](#0-7) 

## Proof of Concept
1. Deploy `OmniBridgeWormhole` with `TestWormhole` as the Wormhole address (`messageFee = 10000 wei`).
2. Prepare a valid `TransferMessagePayload` signed by `nearBridgeDerivedAddress` with `tokenAddress = address(0)` and `amount = 1 ether`.
3. Call `finTransfer{value: 1 ether + 10000}(sig, payload)`.
4. Base contract sends `1 ether` to `payload.recipient` — contract balance is now `10000 wei`.
5. `finTransferExtension` calls `_wormhole.publishMessage{value: 1 ether + 10000}(...)`.
6. EVM reverts: contract holds only `10000 wei` but attempts to forward `1 ether + 10000 wei`.
7. Entire transaction reverts; nonce is not consumed; the transfer is permanently unfinalizeable via this path. [9](#0-8)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L387-391)
```text
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L96-116)
```text
    function finTransferExtension(
        BridgeTypes.TransferMessagePayload memory payload
    ) internal override {
        bytes memory messagePayload = bytes.concat(
            bytes1(uint8(MessageType.FinTransfer)),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            Borsh.encodeString(payload.feeRecipient)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );

        wormholeNonce++;
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

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L13-13)
```text
        require(msg.value == this.messageFee(), "invalid fee");
```
