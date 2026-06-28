### Title
`finTransferExtension` Uses Full `msg.value` After ETH Already Sent to Recipient, Permanently Freezing Native-ETH Transfers on Wormhole Chains — (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

---

### Summary

`OmniBridgeWormhole.finTransferExtension` forwards the full original `msg.value` to the Wormhole `publishMessage` call. When the transfer token is native ETH (`tokenAddress == address(0)`), the base `finTransfer` already spends `payload.amount` ETH sending it to the recipient. The contract then has only `msg.value − payload.amount` ETH remaining, but `finTransferExtension` tries to forward `msg.value` — an amount the contract no longer holds. The call reverts unconditionally for every native-ETH finalization on Wormhole-connected chains, permanently freezing the user's funds on NEAR.

---

### Finding Description

`OmniBridge.finTransfer` is `payable` and handles native ETH by sending `payload.amount` ETH directly to the recipient: [1](#0-0) 

After that transfer, control passes to `finTransferExtension`: [2](#0-1) 

In `OmniBridgeWormhole`, that extension publishes a Wormhole message using the **full original `msg.value`**: [3](#0-2) 

At the point `finTransferExtension` executes, the contract's ETH balance is `msg.value − payload.amount`. Forwarding `msg.value` to Wormhole requires ETH the contract no longer holds, so the call reverts. No value of `msg.value` supplied by the relayer can satisfy both the recipient payment and the Wormhole fee simultaneously.

By contrast, `initTransferExtension` correctly separates the two concerns: it receives a pre-computed `value` parameter (= `msg.value − nativeFee`) and forwards only that residual to Wormhole: [4](#0-3) 

`finTransferExtension` has no equivalent parameter and blindly re-uses `msg.value`.

---

### Impact Explanation

Every attempt to finalize a NEAR → Wormhole-chain transfer of native ETH (e.g., ETH on Arbitrum/Base, MATIC on Polygon, BNB on BNB Chain) reverts. Because the NEAR contract locks or burns the user's tokens at `init_transfer` time and provides no cancel/refund path for a failed EVM-side finalization, the user's funds are permanently frozen on NEAR. This satisfies the **permanent freezing of bridged funds** criterion.

---

### Likelihood Explanation

Any user who bridges native ETH from NEAR to a Wormhole-connected chain triggers this path. The `OmniBridgeWormhole` contract is the deployed implementation for Arbitrum, Base, Polygon, and BNB Chain — all high-traffic chains. No special attacker capability is required; a normal user initiating a standard native-ETH bridge transfer is sufficient.

---

### Recommendation

Pass the remaining ETH (after the recipient payment) into `finTransferExtension` as an explicit parameter, mirroring the pattern already used in `initTransferExtension`:

```solidity
// In OmniBridge.finTransfer, compute remaining value:
uint256 remainingValue = msg.value;
if (payload.tokenAddress == address(0)) {
    remainingValue = msg.value - payload.amount; // amount already sent to recipient
}
finTransferExtension(payload, remainingValue);

// In OmniBridgeWormhole.finTransferExtension:
function finTransferExtension(
    BridgeTypes.TransferMessagePayload memory payload,
    uint256 value          // <-- new parameter
) internal override {
    _wormhole.publishMessage{value: value}(...);
}
```

---

### Proof of Concept

1. User on NEAR initiates a transfer of 1 ETH to their Arbitrum address. Tokens are locked on NEAR; MPC signs the payload.
2. Relayer calls `OmniBridgeWormhole.finTransfer` on Arbitrum, sending `msg.value = 1 ETH + wormhole_fee`.
3. Base `finTransfer` executes: `payload.recipient.call{value: 1 ETH}("")` succeeds; contract now holds only `wormhole_fee` ETH.
4. `finTransferExtension` executes: `_wormhole.publishMessage{value: msg.value}(...)` = `{value: 1 ETH + wormhole_fee}` — contract cannot forward more ETH than it holds → **revert**.
5. Relayer's ETH is returned; user's 1 ETH remains locked on NEAR with no recovery path.

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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L108-113)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L142-147)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```
