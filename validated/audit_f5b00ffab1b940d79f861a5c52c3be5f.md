### Title
ERC-1155 `onERC1155Received` Callback in `finTransfer` Permanently Freezes Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.finTransfer` delivers ERC-1155 tokens to the recipient using `IERC1155.safeTransferFrom`, which mandatorily invokes the `onERC1155Received` callback on any contract recipient. A malicious or non-compliant contract recipient can revert inside that callback, causing the entire `finTransfer` transaction to revert. Because the nonce-marking write (`completedTransfers[nonce] = true`) is also reverted, the nonce is never consumed, yet the recipient address is immutably fixed in the MPC-signed payload. The result is that the ERC-1155 tokens are permanently frozen inside the bridge contract with no recovery path.

### Finding Description

In `finTransfer`, the nonce is marked used at line 287 and then the ERC-1155 branch executes at lines 323–330:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
// ...
} else if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(  // line 324
        address(this),
        payload.recipient,
        multiToken.tokenId,
        payload.amount,
        ""
    );
}
```

`IERC1155.safeTransferFrom` is specified by EIP-1155 to call `onERC1155Received` on any contract recipient and to revert if the hook does not return the correct selector. If the recipient contract:

- deliberately reverts in `onERC1155Received`, or
- does not implement `IERC1155Receiver` at all (e.g., a multisig, a DeFi vault, a DAO contract),

the entire `finTransfer` call reverts atomically, unwinding the `completedTransfers` write as well.

The `payload.recipient` is part of the Borsh-encoded message that was signed by the MPC-derived key (`nearBridgeDerivedAddress`). No alternative recipient can be substituted without a fresh MPC signature. There is no admin rescue function, no pull-payment fallback, and no way to re-route the delivery. The ERC-1155 tokens remain locked in the bridge contract indefinitely.

The same structural issue exists for the native-ETH branch (lines 319–322): if `payload.recipient` is a contract that rejects ETH, `FailedToSendEther` is thrown, the transaction reverts, and the ETH is permanently frozen.

### Impact Explanation

- **Permanent freezing of bridged ERC-1155 (and native ETH) funds.** The source-chain tokens (on NEAR) are already burned or locked at the time `finTransfer` is called. If delivery on the EVM side can never succeed, those assets are irrecoverably lost.
- This satisfies the allowed critical impact: *"permanent freezing of bridged funds across … EVM … flows."*

### Likelihood Explanation

ERC-1155 transfers to contract addresses are a normal use-case (DeFi integrations, multisigs, DAO treasuries). Many such contracts do not implement `IERC1155Receiver`. A user who specifies any such contract as the NEAR-to-EVM recipient triggers permanent loss with no malicious intent required. A deliberate attacker can also deploy a contract that conditionally reverts to extort the protocol or grief specific transfers.

### Recommendation

Replace `safeTransferFrom` with a pull-payment (escrow) pattern for contract recipients:

1. In the ERC-1155 branch, attempt delivery with a try/catch. On failure, credit the amount to a per-recipient claimable balance mapping.
2. Expose a separate `claimTokens(address token, uint256 tokenId)` function that lets the recipient pull their tokens.
3. Apply the same pattern to the native-ETH branch (use a claimable-ETH mapping instead of reverting on failed `.call`).

### Proof of Concept

1. Alice holds ERC-1155 token `(tokenAddress, tokenId=7)` on NEAR (previously bridged from EVM).
2. Alice initiates a transfer back to EVM, specifying `recipient = MaliciousContract` (a contract whose `onERC1155Received` always reverts).
3. The MPC signs a `TransferMessagePayload` with `recipient = MaliciousContract`.
4. A relayer calls `finTransfer(signature, payload)`.
5. Execution reaches line 324: `IERC1155(multiToken.tokenAddress).safeTransferFrom(address(this), MaliciousContract, 7, amount, "")`.
6. `MaliciousContract.onERC1155Received` reverts.
7. The entire transaction reverts; `completedTransfers[nonce]` is reset to `false`.
8. No alternative recipient can be used (payload is MPC-signed). No admin rescue exists.
9. The ERC-1155 tokens are permanently locked in the bridge. Alice's NEAR-side tokens are already burned. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L311-313)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-330)
```text
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
