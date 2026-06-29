### Title
ERC1155 `finTransfer` Permanently Locks Bridged Funds When Recipient Contract Lacks `onERC1155Received` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.sol::finTransfer` uses `IERC1155.safeTransferFrom` to deliver ERC1155 multi-tokens to the recipient. If the recipient is a contract that does not implement `IERC1155Receiver`, the `safeTransferFrom` call always reverts. Because the recipient address is embedded in the MPC-signed payload and cannot be altered, the ERC1155 tokens are permanently locked inside the bridge contract on EVM while the corresponding tokens on the source chain have already been burned or locked.

### Finding Description

`OmniBridge` supports ERC1155 tokens via `initTransfer1155` / `finTransfer`. When `finTransfer` is called and the `payload.tokenAddress` maps to a registered `MultiTokenInfo`, the bridge executes:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);
``` [1](#0-0) 

The ERC1155 standard's `safeTransferFrom` calls `onERC1155Received` on the recipient if it is a contract. If the recipient contract does not implement `IERC1155Receiver`, the call reverts with `"ERC1155: transfer to non ERC1155Receiver implementer"`.

The nonce is marked used at line 287 before the transfer, but because Solidity reverts atomically, `completedTransfers[payload.destinationNonce]` is also rolled back: [2](#0-1) 

This means the nonce is never permanently consumed, but every retry of `finTransfer` with the same signed payload will also revert — the recipient address is part of the Borsh-encoded, MPC-signed message and cannot be changed: [3](#0-2) 

`OmniBridge` itself implements `onERC1155Received` but deliberately rejects any transfer where `operator != address(this)`: [4](#0-3) 

There is no admin rescue path or recipient-override mechanism in the contract.

### Impact Explanation

A user who specifies a contract address as the EVM recipient for an ERC1155 bridge-back transfer — e.g., a multisig wallet, a DAO treasury, or any DeFi protocol that does not implement `IERC1155Receiver` — will have their funds permanently frozen:

- The ERC1155 tokens remain locked inside the `OmniBridge` contract on EVM.
- The corresponding tokens on the source chain (NEAR) are already burned or locked by the time `finTransfer` is attempted.
- No recovery function exists; the MPC signature cannot be reissued for a different recipient.

This constitutes **permanent freezing of bridged funds**, matching the critical impact tier.

### Likelihood Explanation

ERC1155 bridging is a production feature of `OmniBridge`. Many common contract types — Gnosis Safe multisigs, DAO treasuries, yield aggregators, and NFT marketplaces — do not implement `IERC1155Receiver`. A user who bridges ERC1155 tokens to any such contract address triggers the permanent lock. No special attacker capability is required; the user only needs to specify a contract recipient when initiating the bridge transfer on NEAR.

### Recommendation

Replace `safeTransferFrom` with the non-safe variant `transferFrom` for ERC1155 delivery in `finTransfer`, or add a try/catch fallback that stores undeliverable tokens for manual claim by the recipient. Alternatively, validate at `initTransfer1155` time (on EVM) or at the NEAR signing stage that the EVM recipient either is an EOA or implements `IERC1155Receiver` before committing the transfer.

### Proof of Concept

1. User holds ERC1155 token (e.g., `tokenId = 7`) on EVM and bridges it to NEAR via `initTransfer1155`. Tokens are escrowed in `OmniBridge`.
2. On NEAR, the bridge mints the bridged representation to the user.
3. User initiates a bridge-back from NEAR, specifying a Gnosis Safe multisig address (which does not implement `IERC1155Receiver`) as the EVM recipient. NEAR burns the tokens.
4. Relayer obtains MPC signature and calls `finTransfer` on EVM.
5. `finTransfer` reaches line 324 and calls `IERC1155(multiToken.tokenAddress).safeTransferFrom(address(this), gnosisSafe, 7, amount, "")`.
6. The ERC1155 token contract calls `onERC1155Received` on the Gnosis Safe; the Safe does not implement it; the call reverts.
7. The entire `finTransfer` transaction reverts. `completedTransfers[nonce]` is rolled back.
8. Every subsequent retry reverts identically — the signed payload is immutable.
9. The ERC1155 tokens are permanently locked in `OmniBridge`; the NEAR tokens are already burned. [5](#0-4)

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
