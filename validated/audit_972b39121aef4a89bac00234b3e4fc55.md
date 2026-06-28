### Title
`OmniBridgeWormhole.finTransferExtension` forwards full `msg.value` to Wormhole after already spending `payload.amount` on native-ETH delivery, permanently blocking native-ETH finalization - (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

### Summary

`OmniBridgeWormhole.finTransferExtension` unconditionally forwards `msg.value` to `_wormhole.publishMessage`. When `finTransfer` is called with `tokenAddress == address(0)` (native ETH), the base contract first spends `payload.amount` of ETH sending it to the recipient, leaving only `wormhole_fee` in the contract from the current call. `finTransferExtension` then tries to forward the original `msg.value` (= `payload.amount + wormhole_fee`) to Wormhole, which requires exactly `messageFee()`. Because `msg.value > messageFee()`, the Wormhole call reverts, causing the entire `finTransfer` to revert. Every attempt to finalize a native-ETH transfer on a Wormhole chain will fail permanently.

### Finding Description

`OmniBridge.finTransfer` is `external payable` and handles native ETH delivery when `payload.tokenAddress == address(0)`: [1](#0-0) 

After sending `payload.amount` to the recipient, it calls `finTransferExtension(payload)`. In `OmniBridgeWormhole`, that extension unconditionally forwards `msg.value` to Wormhole: [2](#0-1) 

For a native-ETH finalization the relayer must supply `msg.value = payload.amount + wormhole_fee`. After the base contract spends `payload.amount` on the recipient, only `wormhole_fee` remains from the current call. `finTransferExtension` then attempts `_wormhole.publishMessage{value: msg.value}(...)` — forwarding `payload.amount + wormhole_fee` — but the real Wormhole contract enforces `msg.value == messageFee()` (confirmed by the in-repo test stub): [3](#0-2) 

The call reverts. Because the revert unwinds the entire transaction, `completedTransfers[payload.destinationNonce]` is also rolled back, so the nonce is never consumed — but every retry fails for the same reason. The transfer is permanently unfinalizeable.

Contrast with `initTransferExtension`, which correctly passes only the residual `value` (already stripped of `amount` and `nativeFee`) to Wormhole: [4](#0-3) 

`finTransferExtension` has no equivalent stripping logic.

### Impact Explanation

Any user who bridges native ETH (or the native token of an Arbitrum/Base/Polygon/BNB chain) from NEAR to a Wormhole-connected chain will have their funds permanently frozen. The MPC-signed payload fixes `tokenAddress = address(0)` and `amount`; neither the relayer nor the user can alter them. No retry path exists. This is a permanent, irrecoverable loss of bridged native-ETH funds.

### Likelihood Explanation

The Wormhole variant is deployed on Arbitrum, Base, Polygon, and BNB — all chains where native ETH (or MATIC/BNB) bridging is a natural user action. Any user who initiates a NEAR → EVM native-token transfer on one of these chains triggers the bug deterministically. No special attacker capability is required; a normal bridge user suffices.

### Recommendation

Pass only the Wormhole fee to `finTransferExtension`, not the full `msg.value`. Mirror the pattern already used in `initTransferExtension`: compute `extensionValue = msg.value - (tokenAddress == address(0) ? payload.amount : 0)` before calling `finTransferExtension`, thread it through as a parameter, and use it in `_wormhole.publishMessage{value: extensionValue}(...)`.

### Proof of Concept

1. User bridges 1 ETH from NEAR to Arbitrum (Wormhole chain). MPC signs a payload with `tokenAddress = address(0)`, `amount = 1 ETH`.
2. Relayer calls `OmniBridgeWormhole.finTransfer(sig, payload)` with `msg.value = 1 ETH + 10_000 wei` (Wormhole fee).
3. Base `finTransfer` sends `1 ETH` to `payload.recipient`. Contract balance from this call: `10_000 wei`.
4. `finTransferExtension` calls `_wormhole.publishMessage{value: 1 ETH + 10_000 wei}(...)`.
5. Wormhole enforces `require(msg.value == messageFee())` → `1 ETH + 10_000 != 10_000` → revert.
6. Entire transaction reverts. Nonce not consumed. Retry → same revert. User's ETH is permanently frozen on NEAR.

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

**File:** evm/src/omni-bridge/contracts/test/TestWormhole.sol (L12-14)
```text
    ) external payable returns (uint64) {
        require(msg.value == this.messageFee(), "invalid fee");
        emit MessagePublished(nonce, payload, consistencyLevel);
```
