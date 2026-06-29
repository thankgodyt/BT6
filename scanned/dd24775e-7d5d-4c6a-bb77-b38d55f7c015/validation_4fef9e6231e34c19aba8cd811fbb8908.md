### Title
Malicious ERC1155 Recipient Can Permanently Freeze Bridged Funds via `onERC1155Received` Hook Revert — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `finTransfer` function transfers ERC1155 tokens to the destination recipient using `IERC1155.safeTransferFrom`, which mandatorily invokes `onERC1155Received` on the recipient contract. A malicious recipient can revert inside that hook, causing the entire `finTransfer` transaction to revert. Because the nonce-consumed flag (`completedTransfers[payload.destinationNonce] = true`) is written before the transfer but is rolled back on revert, the nonce is never consumed. No alternative finalization path exists, so the sender's funds are permanently frozen on the source chain.

---

### Finding Description

`finTransfer` marks the destination nonce as used at line 287, then performs the token delivery. For ERC1155 tokens the delivery path is:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,   // attacker-controlled contract
    multiToken.tokenId,
    payload.amount,
    ""
);
```

The ERC1155 standard requires the recipient to implement `IERC1155Receiver.onERC1155Received`; if that function reverts, the entire call reverts. Because Solidity reverts undo all state changes in the same transaction, the `completedTransfers[payload.destinationNonce] = true` write is also rolled back. The nonce therefore remains unconsumed, but the transfer can never succeed because every retry hits the same revert. The sender's tokens, already locked or burned on NEAR when `init_transfer` was called, have no recovery path.

The same structural issue applies to the native-ETH path:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
```

A recipient whose `receive()` / fallback reverts causes `success == false`, which triggers `revert FailedToSendEther()`, again rolling back the nonce flag.

---

### Impact Explanation

Once a user initiates a transfer from NEAR (tokens locked/burned), the only way to release them is a successful `finTransfer` on the destination EVM chain. If the EVM recipient is a contract that always reverts in `onERC1155Received` (or its ETH fallback), `finTransfer` can never succeed, the nonce is never consumed, and the NEAR-side tokens are permanently frozen with no admin-accessible cancellation or refund path in the NEAR contract. This constitutes **permanent freezing of bridged funds**, which is within the critical impact scope.

---

### Likelihood Explanation

Any user who bridges ERC1155 tokens (or native ETH) to a contract address on EVM is exposed. The recipient address is embedded in the MPC-signed payload and cannot be changed after signing. A malicious counterparty who is designated as the EVM recipient (e.g., in a DeFi protocol interaction, an escrow, or a cross-chain swap) can deploy a contract that unconditionally reverts in `onERC1155Received`, permanently locking the sender's funds. No privileged access is required; the attacker only needs to be the designated EVM recipient.

---

### Recommendation

1. **Wrap the token delivery in a try/catch** (Solidity ≥ 0.8) and, on failure, emit a `FinTransferFailed` event and mark the nonce as used anyway, so the transfer is not retried indefinitely.
2. **Add a refund / rescue path on NEAR** that allows the sender to reclaim locked tokens when a destination-chain finalization has provably failed (analogous to the `FailedFinTransferEvent` path that already exists for the NEAR-recipient flow in `fin_transfer_send_tokens_callback`).
3. For the ERC1155 path specifically, consider using a low-level call instead of `safeTransferFrom` and checking the return value, or pulling tokens to an intermediate escrow that the recipient must claim, removing the mandatory callback.

---

### Proof of Concept

**Setup:**
- Deploy a malicious EVM contract `MaliciousReceiver` that implements `onERC1155Received` and always reverts.
- On NEAR, call `ft_on_transfer` → `init_transfer` to bridge ERC1155 tokens to `MaliciousReceiver`'s address. Tokens are locked on NEAR.
- MPC signs the transfer; relayer calls `finTransfer` on EVM.

**Execution:**

```solidity
// MaliciousReceiver.sol
function onERC1155Received(
    address, address, uint256, uint256, bytes calldata
) external pure returns (bytes4) {
    revert("blocked");
}
```

`finTransfer` reaches line 324: [1](#0-0) 

`safeTransferFrom` calls `MaliciousReceiver.onERC1155Received`, which reverts. The entire transaction reverts, including the nonce flag set at line 287: [2](#0-1) 

Every subsequent relay attempt produces the same revert. The NEAR-side tokens remain locked permanently. The NEAR contract's `fin_transfer_send_tokens_callback` refund logic (which handles failed NEAR-recipient transfers) is never reached for EVM-recipient transfers: [3](#0-2) 

because `process_fin_transfer_to_other_chain` is the code path taken for non-NEAR recipients, and it has no analogous failure-recovery mechanism: [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
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

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```

**File:** near/omni-bridge/src/lib.rs (L1980-1985)
```rust
    fn process_fin_transfer_to_other_chain(
        &mut self,
        predecessor_account_id: AccountId,
        transfer_message: TransferMessage,
    ) {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```
