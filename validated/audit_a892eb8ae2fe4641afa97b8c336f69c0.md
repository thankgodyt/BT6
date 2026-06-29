Audit Report

## Title
Native ETH `finTransfer` Permanently Blocked by Double-Spending of `msg.value` in Wormhole Fee Forwarding - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

## Summary

`OmniBridge.finTransfer` sends `payload.amount` ETH to the recipient before invoking `finTransferExtension`. `OmniBridgeWormhole.finTransferExtension` then attempts to forward the full original `msg.value` to Wormhole's `publishMessage`, but the contract's balance at that point is only `msg.value - payload.amount`. The EVM reverts on every native ETH finalization call, permanently preventing delivery of ETH bridged from NEAR via the Wormhole path.

## Finding Description

In `OmniBridge.finTransfer` (lines 317–357 of `OmniBridge.sol`), when `payload.tokenAddress == address(0)`, the contract transfers `payload.amount` ETH to `payload.recipient` via a low-level call before invoking `finTransferExtension`:

```solidity
// OmniBridge.sol L317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
// ...
finTransferExtension(payload);  // L357
```

`OmniBridgeWormhole.finTransferExtension` (lines 96–116 of `OmniBridgeWormhole.sol`) unconditionally forwards the full original `msg.value` to Wormhole:

```solidity
// OmniBridgeWormhole.sol L109-113
_wormhole.publishMessage{value: msg.value}(
    wormholeNonce,
    messagePayload,
    _consistencyLevel
);
```

At the point `finTransferExtension` executes, the contract's ETH balance is `msg.value - payload.amount`. The `{value: msg.value}` sub-call requires the contract to hold `msg.value` ETH, but it only holds `msg.value - payload.amount`. The EVM reverts with an insufficient-balance error for any `payload.amount > 0`.

The `TestWormhole` mock (and the real Wormhole contract) enforces an exact fee check:

```solidity
// TestWormhole.sol L13
require(msg.value == this.messageFee(), "invalid fee");
```

Even if the balance issue were somehow bypassed, forwarding `msg.value` (which includes `payload.amount`) instead of just `messageFee()` would still cause a revert. There is no code path in `finTransfer` or `finTransferExtension` that separates the Wormhole fee from the ETH amount owed to the recipient. The `completedTransfers` nonce is set before the ETH transfer (line 287), so the entire transaction reverts atomically — the nonce is not consumed — but every retry also reverts, making the transfer permanently unfinalizeable.

## Impact Explanation

Every call to `finTransfer` on `OmniBridgeWormhole` where `payload.tokenAddress == address(0)` reverts deterministically at the Wormhole `publishMessage` step. Users who lock or burn native ETH on NEAR expecting delivery on the EVM side via the Wormhole path cannot receive their funds. No relayer or user can successfully finalize such a transfer. This constitutes permanent freezing of bridged ETH, matching the Critical impact class: "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds."

## Likelihood Explanation

The bug is triggered deterministically on every native ETH `finTransfer` call — no special conditions, no access control, no race conditions required. Any relayer or user can call `finTransfer` (it is a public, permissionless function) and observe the revert. The failure mode is 100% reproducible for all native ETH payloads with `amount > 0`.

## Recommendation

In `finTransferExtension`, forward only the Wormhole message fee rather than the full `msg.value`. The caller of `finTransfer` must supply `msg.value = payload.amount + wormholeFee` for native ETH transfers:

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

Additionally, `finTransfer` should validate that `msg.value >= payload.amount + wormholeFee` when `tokenAddress == address(0)` to ensure the contract holds sufficient ETH for both the recipient transfer and the Wormhole fee.

## Proof of Concept

1. Deploy `OmniBridgeWormhole` with `TestWormhole` as the Wormhole address (`messageFee = 10000 wei`).
2. Prepare a valid `TransferMessagePayload` with `tokenAddress = address(0)` and `amount = 1 ether`, signed by `nearBridgeDerivedAddress`.
3. Call `finTransfer{value: 1 ether + 10000}(sig, payload)`.
4. `OmniBridge.finTransfer` executes `payload.recipient.call{value: 1 ether}("")` — contract balance drops to `10000 wei`.
5. `finTransferExtension` executes `_wormhole.publishMessage{value: 1 ether + 10000}(...)`.
6. EVM reverts: contract holds `10000 wei` but the sub-call requires `1 ether + 10000 wei`.
7. Entire transaction reverts. Retry with any `msg.value` also reverts. The transfer is permanently unfinalizeable. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L108-115)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );

        wormholeNonce++;
```

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L13-13)
```text
        require(msg.value == this.messageFee(), "invalid fee");
```
