### Title
Recipient-Controlled Revert in `finTransfer` Permanently Freezes Bridged ETH and ERC1155 Tokens - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.finTransfer()` pushes ETH and ERC1155 tokens directly to `payload.recipient` using patterns that invoke recipient-controlled code. If the recipient is a contract that reverts on ETH receipt or in `onERC1155Received`, the entire `finTransfer` call reverts. Because the MPC-signed payload fixes the recipient address and there is no alternative delivery path, the bridged funds are permanently unclaimable.

### Finding Description
`finTransfer` handles two asset paths that invoke recipient-controlled code:

**ETH path** (lines 317–322):
```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

**ERC1155 path** (lines 323–330):
```solidity
} else if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(
        address(this),
        payload.recipient,
        multiToken.tokenId,
        payload.amount,
        ""
    );
}
```

`safeTransferFrom` mandates that a contract recipient implement `IERC1155Receiver.onERC1155Received` and return the correct selector; any revert or wrong return value causes the call to fail.

In both cases, if the recipient reverts, `finTransfer` reverts entirely. Because Solidity reverts undo all state changes, the `completedTransfers[payload.destinationNonce] = true` write at line 287 is also rolled back. The nonce is therefore never consumed, but the payload is permanently bound to the reverting recipient by the MPC signature — there is no mechanism to re-sign with a different recipient or to rescue the funds via an admin path. [1](#0-0) 

### Impact Explanation
Bridged ETH or ERC1155 tokens destined for a contract recipient that reverts on receipt are permanently frozen inside the bridge. The NEAR side has already burned or locked the originating tokens; the EVM side can never release them. There is no admin override, no alternative delivery path, and no way to obtain a new MPC signature for a different recipient. The result is irreversible loss of the bridged amount for the affected transfer.

### Likelihood Explanation
The scenario is reachable through multiple realistic paths:

1. **Attacker-controlled recipient**: An attacker deploys a contract that initially accepts ETH/ERC1155, advertises it as a DeFi integration, induces a victim to bridge funds to it, then upgrades or self-destructs the contract so it permanently reverts on receipt. The victim's funds are frozen; the attacker need not profit directly — the goal is destruction of the victim's funds.

2. **Accidental incompatible recipient**: A user bridges ETH to a smart-contract wallet, multisig, or protocol contract that lacks a `receive()` function or whose `onERC1155Received` hook reverts under certain conditions (e.g., paused state, access control). Every relay attempt fails and the funds are permanently locked.

Both paths require only a valid MPC-signed payload (obtained through the normal bridge flow) and a recipient address that reverts — no privileged access is needed.

### Recommendation
Apply the pull-over-push pattern: instead of pushing assets to the recipient in `finTransfer`, record the claimable balance in a mapping and expose a separate `claim()` function that the recipient calls. If a push must be retained for UX reasons, add a fallback storage path: on failed delivery, credit the amount to a per-recipient claimable balance rather than reverting, so the nonce is consumed and the funds remain retrievable.

```solidity
// Example fallback for ETH path
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) {
    pendingWithdrawals[payload.recipient] += payload.amount;
}
```

For ERC1155, use a try/catch around `safeTransferFrom` and credit a claimable balance on failure.

### Proof of Concept
1. Attacker deploys `MaliciousRecipient` with a `receive()` that executes `revert()`.
2. Victim initiates a NEAR → EVM bridge transfer of ETH, specifying `MaliciousRecipient` as the EVM recipient.
3. NEAR MPC signs a `TransferMessagePayload` with `tokenAddress = address(0)`, `recipient = MaliciousRecipient`, `amount = X`.
4. Relayer calls `OmniBridge.finTransfer(signature, payload)`.
5. Execution reaches line 319: `payload.recipient.call{value: X}("")` → `MaliciousRecipient.receive()` reverts.
6. `FailedToSendEther` is thrown; the entire transaction reverts, including the `completedTransfers[nonce] = true` write.
7. Every subsequent relay attempt with the same signed payload produces the same revert.
8. The ETH held in the bridge for this transfer is permanently unclaimable; the victim's NEAR-side tokens are already burned. [2](#0-1) [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-330)
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
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```
