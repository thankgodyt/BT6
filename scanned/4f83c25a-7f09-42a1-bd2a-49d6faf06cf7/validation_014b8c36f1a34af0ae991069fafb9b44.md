### Title
Native ETH delivery in `finTransfer` permanently freezes bridged funds when recipient cannot receive ETH - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary
`finTransfer` delivers native ETH to `payload.recipient` via a low-level `.call`. If the recipient is a contract without a `receive()` or `fallback()` function, the call fails and the entire transaction reverts. Because the recipient address is embedded in the MPC-signed payload and cannot be altered, no relayer can ever successfully finalize the transfer. The user's funds locked on NEAR are permanently frozen with no recovery path on the EVM side.

---

### Finding Description
In `finTransfer`, when `payload.tokenAddress == address(0)`, the bridge attempts to push native ETH to the recipient:

```solidity
// OmniBridge.sol line 287
completedTransfers[payload.destinationNonce] = true;

// ... signature verification ...

// OmniBridge.sol lines 317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

The nonce is marked consumed at line 287 before the transfer, but because `revert FailedToSendEther()` rolls back the entire transaction, the nonce is also rolled back. This means the nonce is never consumed — but the signed payload is immutable (the recipient is Borsh-encoded and covered by the MPC signature at line 311). No relayer can substitute a different recipient. Every future call with this payload will revert identically. [2](#0-1) 

In the Wormhole variant (`OmniBridgeWormhole`), `finTransferExtension` publishes the Wormhole confirmation message only after the transfer succeeds. If the transfer always reverts, no confirmation is ever published to NEAR, so the NEAR-side lock is never released. [3](#0-2) 

---

### Impact Explanation
Permanent freezing of bridged native ETH. A user who bridges native tokens from NEAR and specifies a contract address without `receive()` (e.g., a Gnosis Safe, a DAO treasury, a custom contract wallet) as the EVM recipient will have their NEAR-side funds permanently locked. The EVM delivery can never succeed, no Wormhole confirmation is ever emitted, and there is no on-chain mechanism within the EVM bridge to signal failure back to NEAR or to redirect the funds.

---

### Likelihood Explanation
Moderate. Smart contract wallets, multisigs, and protocol treasury contracts are commonly used as bridge recipients. Many such contracts do not implement `receive()` by default. A user bridging to their contract-based account that lacks ETH receive support will trigger this condition. The entry path requires only a standard user action: initiating a NEAR-to-EVM native token bridge transfer with a contract address as recipient.

---

### Recommendation
Replace the hard revert on failed ETH delivery with a pull-payment pattern: store the undeliverable amount in a mapping keyed by `destinationNonce` or `recipient`, mark the nonce as consumed, and allow the recipient (or a designated claimer) to withdraw later. This prevents permanent fund loss while still consuming the nonce and emitting the Wormhole confirmation.

```solidity
mapping(uint64 => PendingEth) public pendingEthDeliveries;

// In finTransfer, replace the revert:
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) {
    pendingEthDeliveries[payload.destinationNonce] = PendingEth(payload.recipient, payload.amount);
}
```

---

### Proof of Concept
1. User on NEAR initiates a native ETH bridge transfer, specifying a Gnosis Safe (or any contract without `receive()`) as the EVM `recipient`.
2. NEAR MPC signs the `TransferMessagePayload` with `tokenAddress = address(0)`, `recipient = <contract without receive>`, and a unique `destinationNonce`.
3. Relayer calls `finTransfer` on EVM, attaching `payload.amount` ETH as `msg.value`.
4. `completedTransfers[nonce] = true` is set, signature is verified successfully.
5. `.call{value: payload.amount}("")` to the recipient fails (no `receive()` function).
6. `FailedToSendEther()` is thrown; entire transaction reverts, including the nonce marking.
7. Relayer retries — same result every time, since the recipient is fixed in the signed payload.
8. `finTransferExtension` (Wormhole confirmation) is never reached; NEAR never receives proof of finalization.
9. User's NEAR-side funds remain permanently locked. No recovery path exists in the EVM contract.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-313)
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
