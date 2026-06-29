### Title
Native ETH Transfer to Non-Payable Contract Recipient Permanently Freezes Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
In `OmniBridge.finTransfer`, when the transfer involves native ETH (`payload.tokenAddress == address(0)`), the contract sends ETH to `payload.recipient` via a low-level `call`. If the recipient is a contract without a `receive()` or `fallback()` function, the call fails and the entire `finTransfer` reverts. Because the recipient address is embedded in an MPC-signed payload that cannot be altered, the transfer can never be finalized, permanently freezing the user's bridged funds.

### Finding Description
In `finTransfer`, the native ETH delivery path is:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

The `payload.recipient` is an EVM address that was specified by the user when initiating the transfer on the NEAR side. It is embedded in the Borsh-encoded message that is signed by the MPC threshold-signature service: [2](#0-1) 

Because the signature covers the recipient address, no relayer or protocol participant can substitute a different recipient without invalidating the MPC signature. If `payload.recipient` is a contract that lacks a `receive()` or `fallback()` function, the `call` returns `success = false`, `FailedToSendEther` is raised, and the entire transaction reverts — including the `completedTransfers[payload.destinationNonce] = true` write at line 287. [3](#0-2) 

The nonce is therefore never consumed, but every subsequent relay attempt will produce the identical revert. The NEAR-side burn/lock of the user's tokens is a separate, already-finalized transaction; there is no rollback path on NEAR.

### Impact Explanation
The user's NEAR tokens are permanently burned or locked, and the corresponding native ETH held by the bridge contract can never be delivered to the intended recipient. The ETH is effectively frozen inside the bridge with no recovery mechanism. This constitutes a **permanent, irrecoverable loss of bridged funds** for the affected user.

### Likelihood Explanation
Contract addresses are common recipients in DeFi: multisig wallets (e.g., Gnosis Safe), DAO treasuries, protocol vaults, and smart-contract wallets are all frequently used as destination addresses. Many such contracts do not implement `receive()`. A user who specifies any such address as their NEAR→EVM native-ETH recipient will lose their funds. No privileged access or special attacker capability is required — any unprivileged bridge user can trigger this condition, even accidentally.

### Recommendation
Replace the push-payment pattern with a **pull-payment (escrow) pattern**: credit the recipient's claimable balance in a mapping and let them withdraw separately. Alternatively, before finalizing, verify that the recipient can accept ETH (e.g., via ERC-165 or a try/catch probe), and if not, hold the ETH in escrow under the recipient's address so it can be claimed later. This mirrors the standard recommendation for the analogous `FathomProxyWalletOwner` issue.

### Proof of Concept
1. User initiates a NEAR → EVM native-ETH transfer, specifying a Gnosis Safe (or any contract without `receive()`) as the EVM `recipient`.
2. The NEAR bridge burns the user's wrapped tokens; the MPC service signs a `TransferMessagePayload` embedding that recipient address.
3. A relayer calls `OmniBridge.finTransfer` with the signed payload.
4. Execution reaches line 319: `payload.recipient.call{value: payload.amount}("")` — the Safe has no `receive()`, so the call returns `(false, "")`.
5. Line 322 reverts with `FailedToSendEther()`. All state changes (including the nonce write) are rolled back.
6. Every subsequent relay attempt with the same signed payload produces the same revert.
7. The user's NEAR tokens are gone; the ETH remains locked in the bridge with no protocol-level recovery path.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-288)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```
