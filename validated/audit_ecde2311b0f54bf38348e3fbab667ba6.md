### Title
Permanent Freezing of Bridged Native ETH When EVM Recipient Contract Lacks `receive`/`fallback` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `finTransfer` function delivers native ETH to the recipient via a low-level `.call`. If the recipient is a contract without a `receive` or `fallback` function, the call fails and the entire transaction reverts. Because the MPC signature permanently binds the recipient address, the transfer can never be completed: the wrapped token is already burned on NEAR, and the ETH remains locked in the bridge contract forever.

---

### Finding Description

In `finTransfer`, when `payload.tokenAddress == address(0)` (native ETH), the contract attempts a bare ETH transfer:

```solidity
if (payload.tokenAddress == address(0)) {
    // slither-disable-next-line arbitrary-send-eth
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

If `payload.recipient` is a contract that does not implement `receive()` or `fallback()`, the call returns `success = false` and the function reverts with `FailedToSendEther`. Because `completedTransfers[payload.destinationNonce] = true` is set before the transfer attempt, the revert also undoes that state write, leaving the nonce unconsumed. [2](#0-1) 

The recipient address is embedded in the Borsh-encoded payload that the NEAR MPC cluster signs. No re-signing to a different recipient is possible. Every subsequent call to `finTransfer` with the same signed payload will revert identically, making the transfer permanently undeliverable.

On the NEAR side, the outbound flow burns the wrapped token (e.g., wrapped ETH) before the MPC signature is requested, via `burn_tokens_if_needed` inside `init_transfer_internal`: [3](#0-2) 

The burn is irreversible. There is no rollback path once the NEAR-side token is destroyed and the MPC has signed the delivery to the undeliverable EVM address.

---

### Impact Explanation

A user bridges wrapped ETH from NEAR to an EVM contract address that lacks `receive`/`fallback`. The wrapped ETH is burned on NEAR. The MPC signs a `finTransfer` payload naming that contract as recipient. Every relayer attempt to call `finTransfer` reverts. The ETH remains locked in the bridge contract indefinitely with no recovery mechanism. This constitutes **permanent freezing of bridged funds**.

---

### Likelihood Explanation

Contract-to-contract bridge interactions are a normal use case. A developer whose contract initiates a NEAR → EVM bridge transfer and specifies their own contract address as the EVM recipient — without implementing `receive()` — will silently lose funds. There is no on-chain warning, no documentation enforcement, and no fallback delivery path (e.g., wrapping to WETH). The scenario is realistic and has no prerequisite beyond a user-controlled recipient field.

---

### Recommendation

Adopt one of the following mitigations:

1. **Wrap-on-failure**: If the bare ETH `.call` fails, wrap the ETH into WETH and transfer WETH to the recipient instead (analogous to the `_sendEthOrWeth` pattern, but with the recipient expected to handle WETH).
2. **Pull-based escrow**: On failure, credit the amount to a per-recipient claimable balance mapping rather than reverting, allowing the recipient to pull funds later.
3. **Enforce EOA recipient**: Validate that `payload.recipient.code.length == 0` before accepting a native-ETH transfer message, rejecting contract recipients at the NEAR signing stage.

---

### Proof of Concept

1. User on NEAR calls `ft_on_transfer` on the wrapped-ETH token contract, specifying `recipient = OmniAddress::Eth(contract_without_fallback)`.
2. `init_transfer_internal` burns the wrapped ETH via `burn_tokens_if_needed` and emits `InitTransferEvent`. [4](#0-3) 
3. The NEAR MPC cluster signs a `TransferMessagePayload` with `tokenAddress = address(0)` and `recipient = contract_without_fallback`.
4. A relayer calls `OmniBridge.finTransfer(signatureData, payload)` on EVM.
5. Execution reaches the ETH branch; `contract_without_fallback.call{value: amount}("")` returns `success = false`.
6. The function reverts with `FailedToSendEther`; `completedTransfers[destinationNonce]` is also reverted. [1](#0-0) 
7. All subsequent relay attempts revert identically. The wrapped ETH is permanently burned on NEAR; the ETH is permanently locked in `OmniBridge.sol`.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-322)
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
```

**File:** near/omni-bridge/src/lib.rs (L1850-1861)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }
```
