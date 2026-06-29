### Title
Missing Zero-Address Validation for `payload.recipient` in `finTransfer` Allows Permanent Loss of Native ETH — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `finTransfer` function in `OmniBridge.sol` performs no check that `payload.recipient != address(0)`. When the token being finalized is native ETH (`payload.tokenAddress == address(0)`), the contract sends ETH directly to `payload.recipient` via a low-level `.call`. If `payload.recipient` is `address(0)`, the call succeeds silently and the ETH is permanently burned, with the nonce marked consumed and no recovery path.

---

### Finding Description

`finTransfer` accepts a Borsh-encoded, MPC-signed `TransferMessagePayload` and dispatches assets to `payload.recipient`. The native-ETH branch is:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

There is no guard of the form `require(payload.recipient != address(0))` anywhere before this branch, or anywhere else in `finTransfer`. [2](#0-1) 

The `recipient` field is typed as `address` in `BridgeTypes.TransferMessagePayload`: [3](#0-2) 

A low-level `.call` to `address(0)` with ETH value always returns `success = true` in the EVM (there is no code at address(0) to reject it), so `FailedToSendEther` is never triggered. The transfer nonce is marked consumed at line 287 before the dispatch: [4](#0-3) 

Once the nonce is consumed and ETH is sent to `address(0)`, the funds are permanently unrecoverable.

---

### Impact Explanation

A user initiating a NEAR → EVM transfer of native ETH who supplies `address(0)` (i.e., the all-zeros hex string `"0x0000000000000000000000000000000000000000"`) as the EVM recipient causes the NEAR bridge to produce and MPC-sign a `TransferMessagePayload` with `recipient = address(0)`. When a relayer submits this payload to `finTransfer`, the ETH is forwarded to `address(0)`, the destination nonce is permanently consumed, and the funds are irrecoverably burned. No admin action can reverse this because the nonce replay guard prevents re-execution.

Impact classification: **permanent loss of bridged funds**.

---

### Likelihood Explanation

The NEAR bridge accepts the EVM recipient as a user-supplied string and encodes it into the signed payload. There is no evidence of a zero-address guard on the NEAR side for EVM recipients. Any user who mistakenly or deliberately passes the zero address as the EVM recipient triggers this path. Relayers are incentivized to submit any valid signed payload, so the finalization step is automatic once the NEAR bridge signs the message. Likelihood is **low-to-moderate** (requires user error or deliberate self-harm, but no protocol-level guard prevents it).

---

### Recommendation

Add an explicit zero-address check at the top of `finTransfer`, before the nonce is consumed:

```solidity
require(payload.recipient != address(0), "ERR_ZERO_RECIPIENT");
```

Additionally, the NEAR bridge should validate that EVM-chain recipients decoded from user input are not the zero address before signing the transfer payload.

---

### Proof of Concept

1. User calls the NEAR bridge's transfer initiation with token = native ETH and `recipient = "0x0000000000000000000000000000000000000000"`.
2. NEAR bridge MPC signs a `TransferMessagePayload` with `recipient = address(0)` and `tokenAddress = address(0)`.
3. Relayer calls `OmniBridge.finTransfer(signatureData, payload)`.
4. Signature check passes (line 311). Nonce marked consumed (line 287).
5. Execution enters the `payload.tokenAddress == address(0)` branch (line 317).
6. `address(0).call{value: payload.amount}("")` returns `(true, "")`.
7. ETH is permanently burned; `FinTransfer` event is emitted with `recipient = address(0)`.
8. Nonce is consumed; no re-execution is possible. [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
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

        finTransferExtension(payload);

        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
    }
```

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L5-14)
```text
    struct TransferMessagePayload {
        uint64 destinationNonce;
        uint8 originChain;
        uint64 originNonce;
        address tokenAddress;
        uint128 amount;
        address recipient;
        string feeRecipient;
        bytes message;
    }
```
