### Title
Excess ETH Not Refunded After Wormhole Fee Payment in Payable Bridge Functions - (File: evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol)

### Summary
`OmniBridgeWormhole` inherits several `payable` functions from `OmniBridge` and overrides the extension hooks to forward ETH to Wormhole's `publishMessage`. In four of these hooks the entire `msg.value` is forwarded verbatim; in the remaining two the computed `extensionValue` is forwarded. Neither path refunds any ETH that exceeds the actual Wormhole `messageFee()`. Any overpayment is permanently absorbed by the Wormhole core contract and is unrecoverable by the caller.

### Finding Description

`OmniBridgeWormhole` overrides four internal extension hooks. Three of them forward the raw `msg.value`:

```solidity
// deployTokenExtension – called from payable deployToken()
_wormhole.publishMessage{value: msg.value}(wormholeNonce, payload, _consistencyLevel);

// logMetadataExtension – called from payable logMetadata() and logMetadata1155()
_wormhole.publishMessage{value: msg.value}(wormholeNonce, payload, _consistencyLevel);

// finTransferExtension – called from payable finTransfer()
_wormhole.publishMessage{value: msg.value}(wormholeNonce, messagePayload, _consistencyLevel);
```

The fourth hook receives a pre-computed `extensionValue` (= `msg.value − nativeFee`, or `msg.value − amount − nativeFee` for native-ETH transfers) and forwards that:

```solidity
// initTransferExtension – called from payable initTransfer() / initTransfer1155()
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
```

Wormhole's `publishMessage` requires payment of at least `messageFee()` but does not refund any surplus. Because `OmniBridgeWormhole` itself also performs no refund, any ETH sent above the Wormhole fee is permanently lost to the caller.

Affected entry points (all `external payable`):
| Function | Forwarded value |
|---|---|
| `deployToken()` | full `msg.value` |
| `logMetadata()` | full `msg.value` |
| `logMetadata1155()` | full `msg.value` |
| `finTransfer()` | full `msg.value` |
| `initTransfer()` | `msg.value − nativeFee` |
| `initTransfer1155()` | `msg.value − nativeFee` |

### Impact Explanation

Any caller who sends `msg.value > wormhole.messageFee()` (or, for `initTransfer`, `msg.value − nativeFee > wormhole.messageFee()`) permanently loses the excess ETH. This is a direct, irreversible financial loss. The most impactful path is `finTransfer`, which is called by relayers to finalize cross-chain transfers; relayers routinely add a small buffer to avoid under-payment reverts, and that buffer is silently confiscated. Over many finalizations the cumulative loss is material. `logMetadata` and `deployToken` are callable by any unprivileged address and carry the same risk.

### Likelihood Explanation

Wormhole's `messageFee()` can change via governance. Callers who cache the fee or add a safety margin will routinely overpay. The entry points are public and require no special role (except `addCustomToken`, which is admin-only and not listed above). The pattern of adding a small ETH buffer to avoid reverts is standard relayer practice, making overpayment the common case rather than the edge case.

### Recommendation

After calling `_wormhole.publishMessage`, compute the actual fee consumed and refund the remainder to `msg.sender`:

```solidity
uint256 fee = _wormhole.messageFee();
_wormhole.publishMessage{value: fee}(wormholeNonce, payload, _consistencyLevel);
uint256 excess = msg.value - fee;   // or: value - fee for initTransferExtension
if (excess > 0) {
    (bool ok, ) = msg.sender.call{value: excess}("");
    require(ok, "ETH refund failed");
}
```

Apply this pattern in every override inside `OmniBridgeWormhole` that calls `publishMessage`.

### Proof of Concept

1. Wormhole `messageFee()` is currently `X` wei.
2. Relayer calls `OmniBridgeWormhole.finTransfer(sig, payload)` with `msg.value = X + 1 ether` (common buffer practice).
3. `finTransferExtension` executes `_wormhole.publishMessage{value: msg.value}(...)`, forwarding `X + 1 ether` to Wormhole.
4. Wormhole accepts the call (it requires `>= messageFee()`), keeps `X + 1 ether`, and returns a sequence number.
5. `OmniBridgeWormhole` performs no refund; the relayer permanently loses `1 ether`.
6. Repeat across all `finTransfer` calls; losses accumulate with no recovery path.

**Root-cause lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Payable entry points that feed these hooks:** [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L62-68)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L86-93)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L108-116)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            messagePayload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L142-149)
```text
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-139)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
        if (tokenImplementationAddress == address(0)) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-283)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-380)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
```
