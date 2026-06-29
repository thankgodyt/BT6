### Title
ERC-1155 `safeTransferFrom` Callback in `finTransfer` Allows Malicious Recipient to Permanently Freeze Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

In `OmniBridge.sol`'s `finTransfer`, when the bridged token is registered as an ERC-1155 multi-token, the contract calls `IERC1155.safeTransferFrom` directly to the user-specified `payload.recipient`. ERC-1155's `safeTransferFrom` mandates that if the recipient is a contract, it must implement `onERC1155Received` and return the correct magic value — otherwise the call reverts. A malicious recipient contract can deliberately revert in this callback, causing the entire `finTransfer` transaction to roll back. Because the nonce-marking (`completedTransfers[payload.destinationNonce] = true`) is also rolled back, the nonce is never permanently consumed, yet the source-chain funds (already burned or locked on NEAR) can never be recovered. The transfer is permanently stuck.

---

### Finding Description

`finTransfer` in `OmniBridge.sol` follows this sequence:

1. **Mark nonce used** (line 287): `completedTransfers[payload.destinationNonce] = true`
2. **Verify MPC signature** (lines 289–313)
3. **Dispatch token delivery** (lines 315–355) — for ERC-1155 multi-tokens:

```solidity
} else if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(
        address(this),
        payload.recipient,   // ← attacker-controlled contract
        multiToken.tokenId,
        payload.amount,
        ""
    );
}
``` [1](#0-0) [2](#0-1) 

`IERC1155.safeTransferFrom` is specified by EIP-1155 to call `onERC1155Received` on any contract recipient and revert if the callee does not return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`. A recipient contract that reverts inside `onERC1155Received` causes the entire `finTransfer` call to revert — including the `completedTransfers` write at line 287.

Consequence: the destination nonce is **never consumed**, so no replay protection blocks a retry. However, the signed payload is immutable (the MPC signed a specific `recipient`), so the relayer cannot substitute a different recipient. Every retry will hit the same revert. Meanwhile, on the NEAR side, the user's tokens were already burned or locked at `init_transfer` time and there is no cancellation path. The funds are permanently frozen.

The `OmniBridgeWormhole` contract inherits `finTransfer` unchanged from `OmniBridge`, so it is equally affected. [3](#0-2) 

---

### Impact Explanation

**Permanent freezing of bridged funds.** The user's tokens are burned/locked on NEAR at `init_transfer`. If `finTransfer` on the EVM side can never succeed — because the recipient contract always reverts the ERC-1155 callback — those tokens are irrecoverable. There is no on-chain cancel or refund path on the NEAR bridge for a transfer whose destination-chain finalization has not yet been proven. This satisfies the critical impact criterion: *permanent freezing of bridged funds across NEAR and EVM*.

---

### Likelihood Explanation

The attack path requires only that `payload.recipient` be a contract that reverts in `onERC1155Received`. This is trivially achievable:

- **Intentional griefing / self-harm**: A user specifies their own malicious contract as recipient, permanently locking their own funds (e.g., to grief the protocol's locked-token accounting or to demonstrate the bug).
- **Accidental incompatibility**: Many widely-deployed contracts — multisig wallets (Gnosis Safe without ERC-1155 module), DAO treasuries, DeFi vaults — do not implement `onERC1155Received`. A user who bridges ERC-1155 tokens to such a contract address loses their funds permanently.
- **Malicious third-party recipient**: If a user is directed (e.g., via a phishing UI) to specify a contract address that appears legitimate but rejects ERC-1155, their funds are frozen with no recourse.

The `recipient` field is part of the MPC-signed payload, so neither the relayer nor the protocol can substitute a safe address after the fact.

---

### Recommendation

Replace the push-based ERC-1155 delivery with a **pull-based escrow pattern**:

1. In `finTransfer`, instead of calling `safeTransferFrom` to `payload.recipient`, record a claimable balance: `claimable[payload.recipient][multiToken.tokenAddress][multiToken.tokenId] += payload.amount`.
2. Expose a separate `claimERC1155(address tokenAddress, uint256 tokenId)` function that the recipient calls to pull their tokens via `safeTransferFrom(address(this), msg.sender, ...)`.

This ensures `finTransfer` never reverts due to recipient-side callback behavior, the nonce is consumed atomically, and recipients can claim at their convenience.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

/// Malicious recipient: always rejects ERC-1155 tokens
contract MaliciousRecipient is IERC1155Receiver {
    function onERC1155Received(
        address, address, uint256, uint256, bytes calldata
    ) external pure override returns (bytes4) {
        revert("I reject your tokens");
    }
    function onERC1155BatchReceived(
        address, address, uint256[] calldata, uint256[] calldata, bytes calldata
    ) external pure override returns (bytes4) {
        revert("I reject your tokens");
    }
    function supportsInterface(bytes4) external pure override returns (bool) {
        return false;
    }
}
```

**Attack sequence:**

1. Attacker deploys `MaliciousRecipient` on the target EVM chain.
2. Attacker initiates a transfer on NEAR via `ft_transfer_call` → `init_transfer_internal`, specifying `MaliciousRecipient`'s address as the EVM recipient. Tokens are burned/locked on NEAR.
3. Relayer calls `finTransfer(signatureData, payload)` on `OmniBridge`. The MPC signature covers `payload.recipient = MaliciousRecipient`.
4. `completedTransfers[nonce] = true` is written (line 287), then `IERC1155.safeTransferFrom(..., MaliciousRecipient, ...)` is called (line 324).
5. `MaliciousRecipient.onERC1155Received` reverts → entire `finTransfer` reverts → `completedTransfers[nonce]` is rolled back.
6. Relayer retries indefinitely; every attempt reverts identically.
7. Source-chain tokens remain burned/locked on NEAR with no recovery path. Funds are permanently frozen. [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-355)
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L26-26)
```text
contract OmniBridgeWormhole is OmniBridge {
```
