### Title
Native ETH `finTransfer` reverts on recipient failure, enabling permanent fund freezing — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.finTransfer` sends native ETH to `payload.recipient` using an uncapped `.call{value: payload.amount}("")`. If the recipient is a contract whose fallback reverts (or consumes all gas), the entire `finTransfer` transaction reverts. Because the nonce-marking write (`completedTransfers[payload.destinationNonce] = true`) is also rolled back, the transfer can never be finalized, permanently freezing the bridged funds that were already locked or burned on NEAR.

### Finding Description

In `OmniBridge.finTransfer`, when `payload.tokenAddress == address(0)` (native ETH transfer), the contract executes:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
``` [1](#0-0) 

Two problems compound here:

1. **No gas cap**: The `.call{}` forwards all remaining gas to the recipient. A malicious or poorly-written recipient fallback can consume the entire gas budget, causing the relayer's transaction to run out of gas (gas griefing).

2. **Hard revert on failure**: If the recipient's fallback reverts (e.g., a multisig or DAO treasury that does not accept ETH, or a contract that deliberately reverts), `FailedToSendEther` is thrown. This rolls back the entire transaction, including the `completedTransfers[payload.destinationNonce] = true` write that was set earlier in the same function. [2](#0-1) 

Because the nonce is never durably marked as used, every subsequent relay attempt hits the same reverting recipient and fails identically. There is no fallback path, no pull-payment pattern, and no cancel/refund mechanism visible in the NEAR hub that would release the locked tokens when EVM finalization is permanently blocked.

### Impact Explanation

Tokens locked or burned on NEAR during `init_transfer` are never recoverable once the EVM `finTransfer` is permanently blocked. The bridged funds are frozen indefinitely. This satisfies the critical impact criterion: **permanent freezing of bridged funds across NEAR → EVM flows**.

Additionally, relayers suffer unbounded gas loss on every retry attempt because the call forwards all remaining gas with no stipend cap.

### Likelihood Explanation

Any native-ETH transfer whose `recipient` is:
- A smart contract wallet or multisig that does not implement a payable fallback,
- A DAO treasury or protocol contract that rejects direct ETH,
- A contract deliberately deployed by an attacker to revert on receipt,

will trigger this path. Smart-contract recipients are common in DeFi. The attacker-controlled entry point is simply specifying such an address as the `recipient` field when initiating a transfer on NEAR — no special privilege is required.

### Recommendation

1. **Cap the gas forwarded**: Use a fixed gas stipend (e.g., `call{gas: 2300, value: payload.amount}`) or use a pull-payment pattern where the recipient claims ETH separately.
2. **Do not revert on send failure**: Instead of `revert FailedToSendEther()`, store the unclaimed ETH in a mapping and allow the recipient to withdraw it later (pull-over-push). This ensures the nonce is durably marked as used and the transfer is considered finalized even if the immediate ETH push fails.

### Proof of Concept

1. Attacker deploys `MaliciousRecipient` on EVM with a fallback that always reverts.
2. Attacker initiates a NEAR → EVM native ETH transfer specifying `MaliciousRecipient` as the EVM recipient. NEAR locks the ETH-equivalent tokens.
3. Relayer calls `OmniBridge.finTransfer` with the signed payload.
4. `completedTransfers[nonce] = true` is written at line 287.
5. Execution reaches line 319: `payload.recipient.call{value: payload.amount}("")` → `MaliciousRecipient.fallback()` reverts.
6. `success == false` → `revert FailedToSendEther()` at line 322 rolls back the entire transaction, including the nonce write.
7. Relayer retries → same outcome. Transfer is permanently unfinalizeable. Funds on NEAR are frozen. [3](#0-2)

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
