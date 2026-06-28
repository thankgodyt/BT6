### Title
Recipient Contract Rejecting ETH Permanently Freezes Bridged Native Funds in `finTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

In `OmniBridge.sol`, the `finTransfer` function sends native ETH to `payload.recipient` via a low-level call and hard-reverts if the call fails. Because the recipient address is cryptographically bound to the MPC signature and cannot be changed, and because no on-chain recovery path exists on either the EVM or NEAR side, a user who specifies a contract recipient that rejects ETH will have their bridged funds permanently frozen.

---

### Finding Description

`finTransfer` handles native ETH delivery as follows:

```solidity
// OmniBridge.sol L317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [1](#0-0) 

`payload.recipient` is fully user-controlled: it is set by the user when calling `init_transfer` (or `ft_transfer_call`) on the NEAR side, and it is Borsh-encoded into the payload that the MPC signs. [2](#0-1) 

If `payload.recipient` is a contract whose `receive()` reverts (or has no `receive()`), every call to `finTransfer` for that transfer will revert with `FailedToSendEther()`. Because the recipient is part of the signed payload, no relayer can substitute a different address without invalidating the MPC signature. [3](#0-2) 

The same class of failure applies to ERC-1155 deliveries: `safeTransferFrom` invokes `onERC1155Received` on the recipient contract, and a revert there propagates identically. [4](#0-3) 

Although `completedTransfers[payload.destinationNonce] = true` is written before the external call (and is therefore reverted on failure, leaving the nonce unconsumed), this provides no relief: the recipient is fixed by the signature, so retrying always produces the same revert. [5](#0-4) 

On the NEAR side, tokens are burned or locked the moment `init_transfer_internal` succeeds. There is no cross-chain callback that restores them when EVM finalization fails, and no public function exists to cancel or redirect a pending outbound transfer. [6](#0-5) 

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

1. User calls `ft_transfer_call` / `init_transfer` on NEAR; tokens are burned/locked and an `InitTransferEvent` is emitted.
2. Relayer calls `finTransfer` on EVM; the call reverts because the recipient contract rejects ETH.
3. The nonce is not consumed, but the recipient is immutably encoded in the MPC signature.
4. No admin function, emergency path, or cross-chain refund mechanism exists to recover the funds.
5. The bridged ETH (or ERC-1155 tokens) are permanently inaccessible.

---

### Likelihood Explanation

**Medium-High.**

- Any user who specifies a smart-contract address that lacks a payable `receive()` function (e.g., a multisig wallet, a DeFi vault, a contract upgraded after the transfer was initiated) triggers this path accidentally.
- A malicious user can deliberately deploy a reverting contract and use it as the recipient to provably destroy their own bridged funds — or to grief a relayer that has pre-paid gas for the finalization.
- The bridge is permissionless; no validation of the recipient address is performed on either chain before the tokens are burned.

---

### Recommendation

Replace the hard-revert pattern with a pull-payment or escrow fallback:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) {
    // Store for later claim; do not revert
    pendingEthWithdrawals[payload.recipient] += payload.amount;
    emit EthDeliveryFailed(payload.destinationNonce, payload.recipient, payload.amount);
}
```

Alternatively, add a permissioned `rescueFailedTransfer` function that allows the original NEAR-side sender (proven via MPC signature) to redirect the funds to a different EVM address.

---

### Proof of Concept

```solidity
// Malicious / misconfigured recipient
contract RejectingRecipient {
    receive() external payable { revert(); }
}

// Attack flow (pseudocode)
// 1. Deploy RejectingRecipient at address 0xDEAD...
// 2. On NEAR: ft_transfer_call → bridge, msg = InitTransfer { recipient: "eth:0xDEAD..." }
//    → NEAR burns tokens, emits InitTransferEvent
// 3. Relayer calls OmniBridge.finTransfer(signature, payload)
//    payload.tokenAddress == address(0), payload.recipient == 0xDEAD...
//    → (bool success,) = 0xDEAD....call{value: amount}("")  // reverts
//    → revert FailedToSendEther()
// 4. Relayer retries — same result every time.
// 5. Funds are permanently frozen: burned on NEAR, undeliverable on EVM.
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
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

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

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

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```
