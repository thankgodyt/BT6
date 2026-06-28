### Title
Native ETH Transfer to Reverting Recipient Permanently Freezes Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.finTransfer()` sends native ETH directly to `payload.recipient` via a low-level `.call`. If the recipient is a contract whose `receive()` or `fallback()` reverts, the entire `finTransfer` transaction reverts. Because there is no WETH-wrapping fallback and no admin recovery path, the ETH amount for that transfer is permanently frozen inside the bridge contract.

### Finding Description

In `finTransfer`, the destination nonce is marked used and then native ETH is pushed to the recipient: [1](#0-0) 

```solidity
completedTransfers[payload.destinationNonce] = true;
``` [2](#0-1) 

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

When `payload.recipient` is a contract that reverts on ETH receipt, `success` is `false`, `FailedToSendEther()` is thrown, and the **entire transaction reverts** — including the `completedTransfers` write. The nonce is therefore never consumed, but every subsequent relay attempt produces the same revert. There is no alternative delivery path (e.g., wrapping ETH as WETH and sending the ERC-20 instead), and no admin rescue function is visible in the contract. The ETH corresponding to that transfer is permanently locked in the bridge.

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

The ETH held by the bridge is a shared pool accumulated from all `initTransfer` calls that locked native ETH on the EVM side. A transfer whose recipient is a reverting contract consumes a slot in that pool indefinitely: the amount can never be delivered, the nonce can never be finalized, and there is no on-chain mechanism to redirect or recover the funds.

### Likelihood Explanation

**Medium.** The recipient EVM address is chosen by the user who initiates the transfer on the NEAR side. Any user can specify a contract address they control (or one that is known to reject ETH, e.g., many multisigs, proxy contracts without a payable fallback, or contracts that deliberately revert). No special privilege is required; the only prerequisite is initiating a NEAR→EVM transfer of native ETH.

### Recommendation

Mirror the fix applied in the referenced Gearbox report: instead of reverting when the ETH push fails, wrap the ETH as WETH and deliver the ERC-20 token to the recipient. Concretely, replace the hard revert with a WETH deposit + transfer:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) {
        // Fallback: wrap as WETH and transfer ERC-20
        IWETH(wethAddress).deposit{value: payload.amount}();
        IERC20(wethAddress).safeTransfer(payload.recipient, payload.amount);
    }
}
```

This guarantees delivery regardless of the recipient's `receive()` implementation and eliminates the freeze vector.

### Proof of Concept

1. Attacker deploys `MaliciousRecipient` on Ethereum:
   ```solidity
   contract MaliciousRecipient {
       receive() external payable { revert("no ETH"); }
   }
   ```
2. Attacker initiates a NEAR→EVM transfer of native ETH, specifying `MaliciousRecipient` as the EVM recipient.
3. The NEAR MPC signs the `TransferMessagePayload` with `tokenAddress = address(0)` and `recipient = MaliciousRecipient`.
4. A relayer calls `OmniBridge.finTransfer(signature, payload)`.
5. Execution reaches line 319; the `.call` returns `success = false`; `FailedToSendEther()` reverts the transaction.
6. `completedTransfers[destinationNonce]` is also reverted — the nonce is never consumed.
7. Every future relay attempt for this transfer produces the same revert.
8. The ETH amount is permanently locked in `OmniBridge`, with no on-chain path to recover or redirect it. [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-322)
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
```
