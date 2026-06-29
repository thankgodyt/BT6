The code confirms the claim. Let me verify the key mechanics:

1. `OmniBridge.finTransfer` sends `payload.amount` to recipient when `tokenAddress == address(0)`, then calls `finTransferExtension(payload)` — with `msg.value` still equal to the original call value. [1](#0-0) [2](#0-1) 

2. `OmniBridgeWormhole.finTransferExtension` forwards the full `msg.value` to Wormhole — not the residual after ETH delivery. [3](#0-2) 

3. `TestWormhole.publishMessage` enforces `msg.value == messageFee()` exactly, and `messageFee()` returns `10000` wei. [4](#0-3) 

4. `initTransfer` correctly strips `amount` before passing `extensionValue` to `initTransferExtension`, which uses the `value` parameter — not `msg.value`. [5](#0-4) [6](#0-5) 

5. The nonce is set before the ETH send and extension call, so a revert rolls it back — no retry path exists. [7](#0-6) 

The vulnerability is real, reachable by any unprivileged relayer, and causes permanent freezing of bridged native-ETH funds.

---

Audit Report

## Title
`finTransferExtension` forwards full `msg.value` to Wormhole after native-ETH delivery, permanently blocking native-ETH finalization - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary
`OmniBridgeWormhole.finTransferExtension` calls `_wormhole.publishMessage{value: msg.value}(...)` using the original `msg.value` of the `finTransfer` call. When `payload.tokenAddress == address(0)`, the base `OmniBridge.finTransfer` first spends `payload.amount` of ETH delivering it to the recipient, then calls `finTransferExtension` — but `msg.value` still equals `payload.amount + wormhole_fee`. Wormhole enforces `msg.value == messageFee()` exactly, so the call reverts. Because the revert unwinds the entire transaction, the nonce is never consumed, and every retry fails identically, permanently freezing the bridged native-ETH.

## Finding Description
`OmniBridge.finTransfer` is `external payable`. When `payload.tokenAddress == address(0)`, it sends `payload.amount` ETH to `payload.recipient` via a low-level call (OmniBridge.sol L317–322), then calls `finTransferExtension(payload)` (L357). In Solidity, `msg.value` inside an internal function retains the value of the originating external call. `OmniBridgeWormhole.finTransferExtension` (L109) therefore forwards `msg.value = payload.amount + wormhole_fee` to `_wormhole.publishMessage`. The Wormhole contract (confirmed by `TestWormhole.sol` L13) enforces `require(msg.value == this.messageFee())`. Since `payload.amount + wormhole_fee ≠ wormhole_fee`, the call reverts. The revert rolls back `completedTransfers[payload.destinationNonce] = true` (set at L287), so the nonce is never consumed and every subsequent retry fails for the same reason.

The asymmetry with `initTransfer` is explicit: `OmniBridge.initTransfer` computes `extensionValue = msg.value - amount - nativeFee` (L391) and passes it as a parameter to `initTransferExtension`, which uses `value` (not `msg.value`) when calling `_wormhole.publishMessage{value: value}(...)` (OmniBridgeWormhole.sol L143). `finTransferExtension` has no equivalent stripping logic.

## Impact Explanation
Any native-ETH (or native-token) transfer finalized on a Wormhole-connected chain (Arbitrum, Base, Polygon, BNB) is permanently unfinalizeable. The MPC-signed payload fixes `tokenAddress = address(0)` and `amount`; neither the relayer nor the user can alter them. No retry path exists because the nonce is never consumed. This constitutes permanent freezing of bridged funds, matching the Critical impact class: "permanent freezing of bridged funds across … Wormhole-routed flows."

## Likelihood Explanation
No special attacker capability is required. Any unprivileged relayer (or the user themselves) calling `finTransfer` with a valid MPC-signed payload for a native-ETH transfer triggers the bug deterministically. The Wormhole variant is deployed on Arbitrum, Base, Polygon, and BNB — all chains where native-token bridging from NEAR is a natural user action. The bug is triggered on every such finalization attempt, with 100% reproducibility.

## Recommendation
Mirror the pattern already used in `initTransfer`/`initTransferExtension`. Before calling `finTransferExtension`, compute the residual value:

```solidity
uint256 extensionValue = payload.tokenAddress == address(0)
    ? msg.value - payload.amount
    : msg.value;
```

Thread `extensionValue` as a parameter through `finTransferExtension` and use it in `_wormhole.publishMessage{value: extensionValue}(...)` instead of `msg.value`. Update the `finTransferExtension` virtual signature in `OmniBridge` accordingly.

## Proof of Concept
1. User bridges 1 ETH from NEAR to Arbitrum. MPC signs a payload with `tokenAddress = address(0)`, `amount = 1 ETH`, `destinationNonce = N`.
2. Relayer calls `OmniBridgeWormhole.finTransfer(sig, payload)` with `msg.value = 1 ETH + 10_000 wei`.
3. `completedTransfers[N]` is set to `true`.
4. Base contract sends `1 ETH` to `payload.recipient`. Contract's net balance from this call: `10_000 wei`.
5. `finTransferExtension` calls `_wormhole.publishMessage{value: 1 ETH + 10_000 wei}(...)`.
6. `TestWormhole` (and the real Wormhole contract) enforces `require(msg.value == messageFee())` → `1 ETH + 10_000 ≠ 10_000` → revert.
7. Entire transaction reverts. `completedTransfers[N]` is rolled back to `false`. Retry → same revert. User's ETH is permanently frozen.

Reproducible with the existing `TestWormhole` stub: deploy `OmniBridgeWormhole` with `TestWormhole` as the wormhole address, call `finTransfer` with `tokenAddress = address(0)` and `msg.value = amount + 10_000`, and observe the revert at the `publishMessage` fee check.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
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

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L13-19)
```text
        require(msg.value == this.messageFee(), "invalid fee");
        emit MessagePublished(nonce, payload, consistencyLevel);
        return 0;
    }

    function messageFee() external pure returns (uint256) {
        return 10000;
```
