### Title
ERC1155 `safeTransferFrom` Callback in `finTransfer` Permanently Freezes Bridged Funds When Recipient Contract Rejects Tokens - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary

In `OmniBridge.finTransfer`, when delivering ERC1155 tokens to a recipient, the bridge calls `IERC1155.safeTransferFrom`, which mandatorily invokes `onERC1155Received` on any contract recipient. If the recipient contract does not implement `IERC1155Receiver` or deliberately reverts in the callback, the entire `finTransfer` call reverts. Because the signed MPC payload permanently encodes the recipient address, the finalization can never succeed for that transfer, and the corresponding NEAR-side tokens are permanently frozen.

### Finding Description

In `finTransfer` at line 287, the nonce is marked completed before the token transfer:

```solidity
completedTransfers[payload.destinationNonce] = true;
```

Then, for ERC1155 tokens (line 323–330):

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

`IERC1155.safeTransferFrom` is mandated by EIP-1155 to call `onERC1155Received` on any contract recipient and revert if the selector is not returned. If `payload.recipient` is a contract that does not implement `IERC1155Receiver` (or reverts in the hook), the entire `finTransfer` transaction reverts, unwinding the nonce marking.

While the nonce is not permanently consumed (it reverts), the signed `TransferMessagePayload` is cryptographically bound to the specific `payload.recipient` address by the MPC/NEAR-derived signature verified at line 311:

```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

The Borsh-encoded message includes `payload.recipient` (line 298). There is no protocol mechanism to re-issue a signature with a corrected recipient. The NEAR-side tokens were already burned or locked when the user initiated the cross-chain transfer. The result is permanent freezing of the bridged ERC1155 tokens.

### Impact Explanation

A user who specifies a contract address as the EVM recipient that does not implement `IERC1155Receiver` (e.g., a multisig wallet, a DeFi protocol, or any contract without the hook) will have their ERC1155 tokens permanently frozen. The NEAR-side tokens are consumed, the EVM finalization always reverts for that signed payload, and there is no on-chain rescue path. This matches the allowed impact: **permanent freezing of bridged funds**.

### Likelihood Explanation

ERC1155 bridging is a supported, production feature of `OmniBridge` (via `initTransfer1155` / `finTransfer` with `multiTokens` mapping). Many common contract wallets (Gnosis Safe, account-abstraction wallets) and DeFi contracts do not implement `IERC1155Receiver`. A user who bridges ERC1155 tokens from NEAR back to such an EVM contract address will trigger this path. No special attacker capability is required — any unprivileged bridge user who specifies a non-compliant contract as recipient triggers the freeze.

### Recommendation

Wrap the `safeTransferFrom` call in a `try/catch` block. On failure, either:
1. Emit a `FinTransferFailed` event and leave the nonce unconsumed so a rescue path (e.g., admin-specified alternative recipient or refund on NEAR) can be triggered, or
2. Fall back to a non-safe `transferFrom` (if the ERC1155 token supports it) to skip the callback, accepting that the recipient may not be notified.

Additionally, add a protocol-level mechanism to re-sign a `finTransfer` payload with a corrected recipient when the original finalization is provably impossible.

### Proof of Concept

1. User holds ERC1155 token `T` (tokenId `42`) on NEAR (bridged from EVM).
2. User calls NEAR bridge to transfer back to EVM, specifying `recipient = address(GnosisSafe)` (a contract without `IERC1155Receiver`).
3. NEAR burns the user's tokens and emits a cross-chain event.
4. Relayer calls `OmniBridge.finTransfer(sig, payload)` where `payload.tokenAddress` maps to the ERC1155 via `multiTokens`.
5. `completedTransfers[nonce] = true` is set (line 287).
6. `IERC1155(multiToken.tokenAddress).safeTransferFrom(bridge, GnosisSafe, 42, amount, "")` is called (line 324).
7. ERC1155 calls `GnosisSafe.onERC1155Received(...)` — GnosisSafe does not implement it → reverts.
8. Entire `finTransfer` reverts; nonce is cleared.
9. Relayer retries — same result every time.
10. User's NEAR-side tokens are gone; EVM tokens are stuck in the bridge forever. [1](#0-0) [2](#0-1) [3](#0-2)

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
