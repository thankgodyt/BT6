### Title
Reverting ETH Recipient Permanently Freezes Bridged Native Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

In `OmniBridge.finTransfer()`, native ETH is delivered to the recipient using a push-based `.call{value}` pattern. If the recipient is a smart contract whose `receive`/`fallback` function reverts, the entire `finTransfer` transaction reverts. Because the recipient address is cryptographically bound inside the MPC-signed payload, no relayer can substitute a different recipient. The transfer can never be finalized on EVM, and the user's tokens — already burned or locked on NEAR — are permanently unrecoverable.

---

### Finding Description

`finTransfer()` marks the nonce consumed and then attempts to push ETH to `payload.recipient`: [1](#0-0) 

```solidity
completedTransfers[payload.destinationNonce] = true;
``` [2](#0-1) 

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

When `payload.recipient` is a contract that reverts on ETH receipt, `revert FailedToSendEther()` unwinds the entire transaction — including the `completedTransfers` write at line 287. The nonce is therefore never consumed, but this provides no relief: the `recipient` field is part of the Borsh-encoded, MPC-signed `TransferMessagePayload`. [3](#0-2) 

The signature check at line 311 enforces that `payload.recipient` cannot be altered by any relayer: [4](#0-3) 

Every future call to `finTransfer` with the same signed payload will revert identically. There is no fallback path, no admin rescue function, and no pull-withdrawal mapping. The ETH held by the bridge contract for this transfer is permanently frozen.

The same structural problem exists for the ERC-1155 path: `safeTransferFrom` calls `onERC1155Received` on the recipient, which reverts if the recipient does not implement the hook, producing the same permanent freeze for ERC-1155 bridged assets. [5](#0-4) 

---

### Impact Explanation

A user who bridges native ETH (or ERC-1155 tokens) from NEAR to an EVM smart contract that lacks a payable `receive`/`fallback` (or `IERC1155Receiver`) will have their assets permanently frozen. The tokens are burned or locked on NEAR at initiation time; the EVM finalization can never succeed; and no on-chain recovery mechanism exists. This constitutes **permanent loss of bridged funds**.

---

### Likelihood Explanation

Smart contracts that do not accept raw ETH are extremely common: multisigs deployed without a payable fallback, ERC-20 token contracts, protocol vaults, and many others. A user who intends to bridge ETH directly into such a contract — a routine DeFi operation — will trigger this condition without any warning. The scenario requires no privileged access and no attacker cooperation; the user's own legitimate action is sufficient.

---

### Recommendation

Replace the push pattern with a pull pattern for native ETH delivery in `finTransfer`:

1. Instead of calling `payload.recipient.call{value: payload.amount}("")` and reverting on failure, credit `ethBalance[payload.recipient] += payload.amount` in a `mapping(address => uint256)`.
2. Add a public `withdrawETH()` function that sends `ethBalance[msg.sender]` to the caller and zeroes the balance.
3. Apply the same pattern to the ERC-1155 `safeTransferFrom` path: catch a revert and store the pending transfer for the recipient to claim.

This ensures that a reverting recipient never blocks finalization and that funds remain claimable rather than frozen.

---

### Proof of Concept

1. User initiates a NEAR → EVM transfer of native ETH, specifying `recipient = address(RevertingContract)` where `RevertingContract` has:
   ```solidity
   receive() external payable { revert(); }
   ```
2. NEAR MPC signs a `TransferMessagePayload` with `tokenAddress = address(0)`, `amount = X`, `recipient = address(RevertingContract)`.
3. Relayer calls `OmniBridge.finTransfer(signatureData, payload)`.
4. Execution reaches line 319: `payload.recipient.call{value: payload.amount}("")` → the callee reverts.
5. Line 322: `revert FailedToSendEther()` unwinds the entire transaction.
6. `completedTransfers[nonce]` is reset to `false`; the ETH remains in the bridge contract.
7. Any subsequent call with the same signed payload produces the identical revert.
8. The user's tokens are permanently locked on NEAR; the ETH in the EVM bridge is permanently frozen. [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-330)
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
