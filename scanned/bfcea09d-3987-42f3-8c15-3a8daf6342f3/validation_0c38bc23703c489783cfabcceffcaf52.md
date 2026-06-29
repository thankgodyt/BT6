### Title
Native ETH Finalization Always Reverts in OmniBridgeWormhole Due to Double-Spending of `msg.value` — (File: `evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol`)

### Summary

`OmniBridgeWormhole.finTransferExtension` forwards the full `msg.value` to the Wormhole core contract as the publication fee. When the bridged asset is native ETH (`tokenAddress == address(0)`), the base `OmniBridge.finTransfer` already spends `payload.amount` of that same `msg.value` to deliver ETH to the recipient before calling `finTransferExtension`. The contract's remaining balance is therefore `msg.value − payload.amount`, which is always less than `msg.value`. The Wormhole `publishMessage` call reverts unconditionally, and because the entire transaction reverts, the EVM-side nonce is never consumed — leaving the corresponding NEAR-side funds permanently locked with no recovery path.

### Finding Description

`OmniBridge.finTransfer` is `external payable` and handles native ETH delivery at lines 317–322:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

After this call the contract's ETH balance has decreased by `payload.amount`. Control then passes to `finTransferExtension` (line 357). In `OmniBridgeWormhole`, that override is:

```solidity
function finTransferExtension(...) internal override {
    ...
    _wormhole.publishMessage{value: msg.value}(...);
    ...
}
```

`msg.value` here is the **original** call-site value, not the remaining balance. The Wormhole core contract requires the caller to transfer exactly `messageFee()` wei. The bridge contract now holds only `msg.value − payload.amount` wei, so the `{value: msg.value}` forward exceeds the available balance and the EVM reverts with an out-of-funds error. Because the revert unwinds all state changes, `completedTransfers[payload.destinationNonce]` is reset to `false`, but the NEAR-side lock/burn that triggered the transfer is already committed and irreversible. No valid `msg.value` can satisfy both constraints simultaneously: any value large enough to cover `payload.amount + wormholeFee` will still cause the Wormhole call to attempt forwarding the full `msg.value` rather than just `wormholeFee`. [1](#0-0) [2](#0-1) 

### Impact Explanation

Any user who initiates a NEAR → EVM bridge transfer of native ETH (i.e., the NEAR bridge produces a signed payload with `tokenAddress == address(0)`) targeting a chain where `OmniBridgeWormhole` is deployed (Arbitrum, Base, Polygon, BNB) will have their funds permanently frozen. The NEAR-side burn/lock is final; the EVM finalization can never succeed regardless of how many times the relayer retries or how much ETH is attached. This constitutes **permanent loss/freezing of bridged funds** — a Critical impact under the allowed scope. [3](#0-2) 

### Likelihood Explanation

The `finTransfer` function is `external payable` and callable by any relayer. The native-ETH branch (`tokenAddress == address(0)`) is an explicitly supported code path in `OmniBridge`. `OmniBridgeWormhole` is the production deployment on all L2 chains. Any user who bridges native ETH from NEAR to one of those chains triggers this path deterministically. No special attacker capability is required — the bug fires for every legitimate native-ETH finalization attempt. [4](#0-3) [5](#0-4) 

### Recommendation

In `OmniBridgeWormhole.finTransferExtension`, the Wormhole fee must be the **residual** ETH after the native-token delivery, not the full `msg.value`. The cleanest fix is to pass the remaining balance explicitly. One approach is to override `finTransfer` in `OmniBridgeWormhole` to compute the Wormhole fee as `msg.value − (tokenAddress == address(0) ? payload.amount : 0)` and forward only that amount. Alternatively, restructure `finTransferExtension` to accept an explicit `wormholeFee` parameter computed in the base `finTransfer` before any ETH is disbursed:

```solidity
// In OmniBridgeWormhole.finTransferExtension, replace:
_wormhole.publishMessage{value: msg.value}(...);
// With:
uint256 wormholeFee = _wormhole.messageFee();
_wormhole.publishMessage{value: wormholeFee}(...);
```

This mirrors the fix applied in the referenced Connext PR 1532 (sending only the residual ETH with the downstream call rather than the full `msg.value`).

### Proof of Concept

1. User on NEAR initiates a transfer of native ETH equivalent (e.g., unwrapped wNEAR mapped to `address(0)` on Arbitrum) for `payload.amount = 1 ether`.
2. NEAR MPC signs a `TransferMessagePayload` with `tokenAddress = address(0)`, `amount = 1e18`, `recipient = <some address>`.
3. Relayer calls `OmniBridgeWormhole.finTransfer(sig, payload)` with `msg.value = 1e18 + 10000` (1 ETH for recipient + Wormhole fee of 10 000 wei).
4. `completedTransfers[nonce] = true` is set.
5. `payload.recipient.call{value: 1e18}("")` succeeds; contract balance is now `10000` wei.
6. `finTransferExtension` calls `_wormhole.publishMessage{value: 1e18 + 10000}(...)` — contract only holds `10000` wei → **revert**.
7. All state is rolled back. Relayer retries with any `msg.value`; step 6 always reverts because `msg.value` always exceeds the post-delivery balance by exactly `payload.amount`. NEAR-side funds remain permanently locked. [2](#0-1) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-282)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-322)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L26-46)
```text
contract OmniBridgeWormhole is OmniBridge {
    IWormhole private _wormhole;
    // https://wormhole.com/docs/build/reference/consistency-levels
    uint8 private _consistencyLevel;
    uint32 public wormholeNonce;

    function initializeWormhole(
        address tokenImplementationAddress,
        address nearBridgeDerivedAddress,
        uint8 omniBridgeChainId,
        address wormholeAddress,
        uint8 consistencyLevel
    ) external initializer {
        initialize(
            tokenImplementationAddress,
            nearBridgeDerivedAddress,
            omniBridgeChainId
        );
        _wormhole = IWormhole(wormholeAddress);
        _consistencyLevel = consistencyLevel;
    }
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
