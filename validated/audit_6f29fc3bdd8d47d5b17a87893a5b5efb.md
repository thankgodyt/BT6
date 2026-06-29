### Title
ERC1155 `safeTransferFrom` Mandatory Receiver Callback in `finTransfer` Permanently Freezes Bridged Funds When Recipient Contract Lacks `IERC1155Receiver` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `finTransfer` function in `OmniBridge.sol` delivers ERC1155 tokens to the recipient using `IERC1155.safeTransferFrom`. The ERC1155 standard mandates that this call invokes `onERC1155Received` on any contract recipient. If the recipient contract does not implement `IERC1155Receiver`, the call reverts, causing the entire `finTransfer` transaction to revert. Because the NEAR side has already locked or burned the tokens before the EVM finalization is attempted, and because no admin rescue path or alternative delivery mechanism exists, the bridged funds are permanently frozen.

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` dispatches ERC1155 token delivery via:

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

The ERC1155 standard (EIP-1155) requires that `safeTransferFrom` call `onERC1155Received` on the recipient when it is a contract, and revert if the call does not return the correct selector. This is an unconditional protocol-level restriction — not a bridge-specific guard — that mirrors the Liquity `_requireValidRecipient` pattern: a transfer to a contract that does not implement the required interface always reverts.

The nonce is marked used immediately before the transfer attempt:

```solidity
completedTransfers[payload.destinationNonce] = true;
``` [2](#0-1) 

Because the entire transaction reverts when `safeTransferFrom` fails, the nonce write is also reverted. The relayer can retry, but every retry will fail identically because the recipient contract's behavior is immutable. There is no admin rescue function, no alternative delivery path, and no mechanism to redirect the transfer to a different recipient. The NEAR side has already committed the lock or burn, so the funds are permanently frozen.

The `OmniBridge` contract itself deliberately does not advertise `IERC1155Receiver` support in `supportsInterface`, and its own `onERC1155Received` hook rejects any operator that is not `address(this)`:

```solidity
function onERC1155Received(
    address operator,
    ...
) external view override returns (bytes4) {
    if (operator != address(this)) {
        revert ERC1155DirectSendNotAllowed();
    }
    return this.onERC1155Received.selector;
}
``` [3](#0-2) 

This design is intentional for the bridge contract itself, but it highlights that the team is aware of the ERC1155 receiver requirement — yet no equivalent guard is applied to the user-supplied `payload.recipient` before `safeTransferFrom` is called.

---

### Impact Explanation

**Critical — permanent freezing of bridged ERC1155 funds.**

A user who bridges ERC1155 tokens from NEAR (or any supported source chain) to an EVM contract address that does not implement `IERC1155Receiver` will have their tokens locked or burned on the source chain with no possibility of recovery on the EVM side. The `finTransfer` call will revert on every relay attempt, and there is no admin function to redirect or rescue the stuck transfer. The loss is total and irreversible.

---

### Likelihood Explanation

**Medium.** The ERC1155 delivery path is activated whenever a token is registered via `logMetadata1155` and a transfer targets that token. A large class of common contract recipients — multisig wallets (e.g., Gnosis Safe prior to ERC1155 support), DAO treasuries, DeFi vaults, and generic proxy contracts — do not implement `IERC1155Receiver`. A user bridging ERC1155 tokens to any such address will permanently lose their funds. The user has no on-chain way to verify whether the target contract implements the required interface before committing the transfer on the NEAR side.

---

### Recommendation

1. **Pull-based delivery**: Replace the `safeTransferFrom` call with a claimable escrow pattern. Store the tokens in a `pendingClaims[recipient]` mapping and let the recipient pull them via a separate `claim()` function. This eliminates the mandatory callback entirely.
2. **Use `transferFrom` instead of `safeTransferFrom`**: The non-safe variant does not invoke `onERC1155Received`, removing the revert risk. This trades the safety check for liveness.
3. **Wrap in try/catch**: Surround the `safeTransferFrom` call in a Solidity `try/catch` block. On failure, store the amount in a claimable mapping rather than reverting the entire transaction, so the nonce is consumed and the relayer is not stuck in an infinite retry loop.

---

### Proof of Concept

1. An ERC1155 token is registered on the bridge via `logMetadata1155(tokenAddress, tokenId)`, creating a `multiTokens` entry for the deterministic address.
2. A user on NEAR calls `ft_transfer_call` (or equivalent) to initiate a bridge transfer of that ERC1155 token, specifying as recipient a deployed EVM contract (e.g., a Gnosis Safe multisig or a DeFi vault) that does not implement `IERC1155Receiver`. The NEAR contract locks or burns the tokens.
3. The relayer constructs a valid MPC-signed `TransferMessagePayload` and calls `finTransfer(signatureData, payload)` on `OmniBridge`.
4. The signature check passes. Execution reaches the ERC1155 branch and calls `IERC1155(multiToken.tokenAddress).safeTransferFrom(address(this), payload.recipient, ...)`.
5. The ERC1155 token contract calls `onERC1155Received` on `payload.recipient`. The recipient contract has no such function; the call reverts.
6. The entire `finTransfer` transaction reverts. `completedTransfers[payload.destinationNonce]` is also reverted to `false`.
7. The relayer retries. Step 4–6 repeat indefinitely.
8. The user's ERC1155 tokens are permanently frozen: burned/locked on NEAR, undeliverable on EVM, with no admin rescue path available. [4](#0-3)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L522-535)
```text
    function onERC1155Received(
        address operator,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // Only accept transfers that were initiated by this contract itself
        if (operator != address(this)) {
            revert ERC1155DirectSendNotAllowed();
        }

        return this.onERC1155Received.selector;
    }
```
