### Title
ERC1155 `safeTransferFrom` in `finTransfer` Permanently Freezes Bridged Tokens When Recipient Is a Contract Without `onERC1155Received` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`finTransfer()` uses `IERC1155.safeTransferFrom()` to deliver ERC1155 tokens to the bridge recipient. If the recipient is a smart contract that does not implement `onERC1155Received()`, the call reverts unconditionally. Because the recipient address is embedded in the MPC-signed payload, no relayer can alter it, and the transfer can never be finalized. The corresponding tokens locked or burned on NEAR are permanently frozen with no on-chain recovery path.

### Finding Description
In `finTransfer()`, when the destination token is an ERC1155 (identified via the `multiTokens` mapping), the bridge delivers tokens using:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);
``` [1](#0-0) 

Per the ERC1155 standard, `safeTransferFrom` calls `onERC1155Received()` on the recipient if it is a contract, and reverts if the hook is absent or returns the wrong selector. Many legitimate smart contract recipients — multisigs, DAOs, vaults, protocol treasuries — do not implement this hook.

The `payload.recipient` is part of the Borsh-encoded message that is verified against the MPC-derived ECDSA signature: [2](#0-1) 

Because the recipient is cryptographically bound to the nonce, no relayer can substitute a different recipient. Every attempt to call `finTransfer` with the original payload will revert at the `safeTransferFrom` call, and the nonce is never durably consumed (the `completedTransfers` write at line 287 is also reverted). The contract has no admin rescue, no alternative delivery path, and no refund mechanism for stuck ERC1155 balances. [3](#0-2) 

### Impact Explanation
Bridged ERC1155 tokens are permanently frozen. The user's assets are locked or burned on NEAR (via `initTransfer1155` on the source chain), and the corresponding EVM-side tokens held by the bridge contract can never be delivered. There is no on-chain recovery function. This constitutes permanent loss of bridged funds.

### Likelihood Explanation
Any user who specifies a smart contract recipient (multisig, DAO, vault, protocol contract) that does not implement `IERC1155Receiver` triggers this condition. This is a common real-world scenario: Gnosis Safe, many DeFi protocols, and generic proxy contracts do not implement `onERC1155Received`. The user need not be malicious — an honest mistake in specifying the recipient address is sufficient.

### Recommendation
Replace `safeTransferFrom` with `transferFrom` (i.e., `IERC1155.safeTransferFrom` → a direct low-level transfer that skips the receiver hook check) in `finTransfer`, mirroring the external report's recommendation for ERC721. Concretely, call the underlying `_safeTransferFrom` equivalent without the receiver callback, or use a try/catch with a fallback delivery mechanism. Additionally, consider adding an admin-callable rescue function to recover ERC1155 tokens from the bridge contract in case of stuck transfers.

### Proof of Concept

1. User holds ERC1155 token (e.g., `tokenAddress = 0xAAA`, `tokenId = 1`) on NEAR and calls `initTransfer1155` on the NEAR bridge, specifying `recipient = 0xVault` (an EVM vault contract without `onERC1155Received`).
2. NEAR bridge locks/burns the tokens and emits a cross-chain event. MPC nodes sign a `TransferMessagePayload` with `recipient = 0xVault`.
3. Relayer calls `finTransfer(signature, payload)` on EVM `OmniBridge`.
4. `completedTransfers[nonce] = true` is written (line 287), then `safeTransferFrom(bridge, 0xVault, tokenId, amount, "")` is called (line 324).
5. `0xVault` has no `onERC1155Received` → ERC1155 token reverts → entire transaction reverts, including the nonce write.
6. Relayer retries indefinitely; every attempt reverts. The ERC1155 tokens remain in the bridge contract. The NEAR-side assets are permanently gone. No admin function exists to recover them. [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-313)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L323-330)
```text
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-464)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );
```
