### Title
Token Transfer Failure in `finTransfer` Permanently Freezes Bridged Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
The `finTransfer` function in `OmniBridge.sol` directly transfers tokens to the recipient without any fallback mechanism. If the transfer fails — e.g., the recipient is blacklisted by USDC, or the recipient is a contract that rejects ETH — the entire transaction reverts. Because the recipient is cryptographically bound in the NEAR MPC signature and there is no cancel/refund path on the NEAR side for failed EVM finalizations, the user's funds are permanently locked on NEAR.

### Finding Description
In `finTransfer`, the nonce is marked used first, then the MPC signature is verified, and finally tokens are transferred directly to `payload.recipient`:

For native ERC20 tokens (the `else` branch): [1](#0-0) 

For native ETH: [2](#0-1) 

For ERC1155 tokens, `safeTransferFrom` is used, which also reverts if the recipient does not implement `IERC1155Receiver`: [3](#0-2) 

When any of these transfers revert, the entire transaction reverts atomically — including the nonce marking at line 287. The nonce is therefore not permanently consumed, and the call can be retried. However, the recipient address is cryptographically bound in the NEAR MPC signature: [4](#0-3) 

The recipient cannot be changed without a new MPC-signed message. The original funds were already burned or locked on NEAR when the transfer was initiated. There is no `cancel_transfer`, `refund_transfer`, or equivalent function anywhere in the NEAR bridge contract that would allow recovery of funds whose EVM finalization permanently fails. The `pending_transfers` map retains the entry, but no public function allows the user to reclaim the locked/burned tokens based on a failed EVM-side delivery. [5](#0-4) 

The identical pattern exists in the Starknet bridge, where `fin_transfer` calls `IERC20Dispatcher.transfer` directly and asserts success — reverting the whole transaction (including `_set_transfer_finalised`) if the transfer returns false: [6](#0-5) 

### Impact Explanation
A user's bridged funds are permanently frozen on NEAR. The user cannot:
1. Recover the funds — no cancel/refund mechanism exists for failed EVM finalizations.
2. Change the recipient — it is fixed in the MPC-signed message.
3. Retry with a different recipient — the original funds are already burned/locked.

This constitutes permanent freezing of bridged funds across NEAR and EVM (and Starknet), which falls squarely within the allowed critical impact scope.

### Likelihood Explanation
Low but non-zero. USDC — a major asset expected to be bridged — implements a blacklist enforced on every `transfer` and `transferFrom`. If a user's EVM recipient address is blacklisted by USDC (e.g., due to OFAC sanctions compliance) between the time the transfer is initiated on NEAR and the time the relayer submits `finTransfer` on EVM, the transfer is permanently blocked with no recovery path. USDC blacklisting is a documented, recurring real-world event. Any token with blacklist functionality bridged through the Omni Bridge is subject to this scenario. The ETH-rejection variant (recipient is a contract with a reverting `receive`) is also reachable by any user who specifies a smart-contract recipient.

### Recommendation
Use the pull pattern: instead of directly transferring tokens to `payload.recipient`, store the tokens in the contract under the recipient's address and expose a separate `claim(tokenAddress)` function. Alternatively, wrap the transfer in a `try/catch` and, on failure, credit the amount to an internal claimable balance:

```solidity
try IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount) {
    // success
} catch {
    claimable[payload.recipient][payload.tokenAddress] += payload.amount;
}
```

This ensures `finTransfer` always succeeds (consuming the nonce), preventing permanent fund lockup regardless of recipient-side token restrictions.

### Proof of Concept
1. User initiates a USDC transfer from NEAR to EVM, specifying EVM address `R` as recipient. The NEAR bridge burns/locks the USDC and stores a `TransferMessage` in `pending_transfers`.
2. The MPC network signs the transfer message, cryptographically binding `R` as the recipient.
3. Between initiation and finalization, USDC blacklists address `R` (e.g., OFAC compliance action).
4. A relayer calls `finTransfer(signature, payload)` on `OmniBridge.sol`.
5. `completedTransfers[payload.destinationNonce] = true` executes (line 287).
6. `IERC20(payload.tokenAddress).safeTransfer(R, amount)` reverts — USDC rejects transfers to blacklisted addresses.
7. The entire transaction reverts, including the nonce marking. The nonce is unconsumed.
8. The relayer retries — same result every time. The transfer can never be finalized.
9. The user's USDC is permanently locked on NEAR. No cancel or refund function exists to recover it.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L287-313)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** starknet/src/omni_bridge.cairo (L250-263)
```text
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );

            if self.is_bridge_token(payload.token_address) {
                IBridgeTokenDispatcher { contract_address: payload.token_address }
                    .mint(payload.recipient, payload.amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
            }
```
