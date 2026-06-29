### Title
ERC1155 `finTransfer` Uses `safeTransferFrom` Forcing `IERC1155Receiver` on Contract Recipients, Permanently Freezing Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer` delivers bridged ERC1155 tokens via `IERC1155.safeTransferFrom`. The ERC1155 standard mandates that `safeTransferFrom` call `onERC1155Received` on any contract recipient and revert if the selector is not returned correctly. Any contract recipient that does not implement `IERC1155Receiver` (Gnosis Safe multisigs, DeFi vaults, DAO treasuries, etc.) will cause every `finTransfer` attempt to revert permanently. Because the NEAR side has already locked or burned the tokens with no EVM-triggered refund path, the user's funds are frozen forever.

---

### Finding Description

In `finTransfer`, after signature verification, the ERC1155 delivery branch is:

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
``` [1](#0-0) 

`IERC1155.safeTransferFrom` is defined by EIP-1155 to unconditionally invoke `onERC1155Received` on any contract recipient and revert if the return value is not `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`. There is no non-safe variant in the ERC1155 standard. Contracts that do not implement `IERC1155Receiver` — including the vast majority of DeFi protocols, multisig wallets, and DAO treasuries — will cause this call to revert every time.

The nonce is marked used before the transfer:

```solidity
completedTransfers[payload.destinationNonce] = true;
``` [2](#0-1) 

Because the revert unwinds the entire transaction, the nonce is not permanently consumed. However, the transfer can **never** succeed: every subsequent `finTransfer` call for this payload will also revert at the same `safeTransferFrom` line. The NEAR side has no mechanism to detect EVM-side finalization failure and issue a refund; the tokens locked or burned on NEAR are permanently unrecoverable.

---

### Impact Explanation

A user who bridges ERC1155 tokens from NEAR to an EVM contract recipient that does not implement `IERC1155Receiver` suffers permanent, irrecoverable loss of their bridged assets. The NEAR-side tokens are locked (or burned for deployed bridge tokens) at `init_transfer` time. No EVM-triggered callback exists to reverse this. The `finTransfer` transaction will revert on every relay attempt, and the nonce can never be finalized. This constitutes permanent freezing of bridged funds.

---

### Likelihood Explanation

ERC1155 tokens are explicitly supported by the bridge via `initTransfer1155` and the `multiTokens` mapping. A user bridging to a Gnosis Safe, a DAO treasury, a yield vault, or any other contract that does not implement `IERC1155Receiver` — a common and reasonable use case — will trigger this condition. The user has no on-chain signal before initiating the NEAR-side transfer that their chosen recipient is incompatible. The likelihood is realistic for any production ERC1155 bridge usage targeting contract recipients.

---

### Recommendation

Replace the mandatory `safeTransferFrom` delivery with a pull-based escrow pattern: hold the ERC1155 tokens in the bridge contract and expose a `claim(uint64 destinationNonce)` function that the recipient (or anyone on their behalf) can call. This removes the forced `IERC1155Receiver` requirement from the finalization path. Alternatively, wrap the `safeTransferFrom` in a try/catch and, on failure, record the unclaimed balance for later withdrawal, ensuring the nonce is still consumed so replay is prevented.

---

### Proof of Concept

1. Alice holds ERC1155 token `(tokenAddress=0xABC, tokenId=7)` on NEAR (represented as a bridge-mapped token).
2. Alice calls `initTransfer1155` on NEAR, specifying her Gnosis Safe (`0xSAFE`) as the EVM recipient. The NEAR-side tokens are locked.
3. The MPC signs the `TransferMessagePayload` with `tokenAddress = deterministicAddress(0xABC, 7)`, `recipient = 0xSAFE`, `amount = N`.
4. A relayer calls `finTransfer(signature, payload)` on `OmniBridge`.
5. `completedTransfers[nonce]` is set to `true`, signature is verified, `multiTokens[deterministicAddress]` resolves to `(0xABC, 7)`.
6. `IERC1155(0xABC).safeTransferFrom(bridge, 0xSAFE, 7, N, "")` is called. Gnosis Safe does not implement `onERC1155Received`; the call reverts with `ERC1155: transfer to non ERC1155Receiver implementer`.
7. The entire transaction reverts. The nonce is not consumed.
8. Every subsequent relay attempt reverts identically.
9. Alice's tokens on NEAR are permanently frozen with no refund path. [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-355)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```
