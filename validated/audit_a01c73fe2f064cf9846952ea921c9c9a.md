### Title
No-Recovery Path for Failed Native-ETH `finTransfer` Permanently Locks Bridged Funds on NEAR — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

When a user initiates a NEAR → EVM transfer of native ETH, the tokens are burned/locked on NEAR at initiation time. On the EVM side, `finTransfer` attempts to push ETH to the recipient via a low-level `call`. If the recipient is a smart contract that lacks a `receive()` or `fallback()` function, the call fails and the entire transaction reverts — including the nonce-consumption guard. Because no relayer can ever successfully finalize the transfer and there is no cancellation or recovery path on NEAR, the user's funds are permanently frozen.

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` marks the nonce as used and then attempts the asset delivery:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287

// ...

if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();            // line 322
}
``` [1](#0-0) 

Because `revert FailedToSendEther()` rolls back the entire transaction, `completedTransfers[payload.destinationNonce]` is also rolled back. The nonce is therefore never consumed, so any relayer can retry — but every retry will produce the same revert if the recipient contract cannot accept ETH.

On the NEAR side, `init_transfer_internal` burns or locks the tokens at initiation time and stores the `TransferMessage` in `pending_transfers`:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
// ...
env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
U128(0)   // ← 0 returned means no refund to the caller
``` [2](#0-1) 

There is no public `cancel_transfer` or equivalent function that would allow the user or any admin to remove the pending entry and return the burned/locked tokens. `remove_transfer_message` is only called internally upon successful finalization or a storage-check failure during initiation: [3](#0-2) 

The same revert-loop applies to ERC-1155 transfers: `safeTransferFrom` requires the recipient to implement `IERC1155Receiver`; if it does not, the call reverts and the same permanent-lock scenario occurs: [4](#0-3) 

---

### Impact Explanation

A user's bridged native ETH (or ERC-1155 tokens) is permanently frozen. The tokens are burned/locked on NEAR at initiation; the EVM `finTransfer` can never succeed; and there is no on-chain path to reclaim the funds. This matches the allowed critical impact: **permanent freezing of bridged funds**.

---

### Likelihood Explanation

Many deployed smart contracts — multisigs, DAOs, vaults, protocol treasuries — intentionally omit `receive()` / `fallback()` to prevent accidental ETH acceptance. A user bridging native ETH to such a contract address (e.g., a Gnosis Safe that has not enabled ETH receipt, or a pure-logic contract) will trigger this condition. The user need not be malicious; the scenario arises from ordinary usage. The attacker-controlled entry path is simply calling `ft_transfer_call` on NEAR with a contract address as the EVM recipient.

---

### Recommendation

Add a user-configurable **recovery address** parameter to the `InitTransferMsg` (analogous to the fix recommended in the external report). If `finTransfer` on EVM fails for native ETH or ERC-1155, the bridge should either:

1. Accept a `recovery` address in the transfer payload and route funds there on failure, **or**
2. Expose a NEAR-side `cancel_transfer` function (with appropriate guards, e.g., after a timeout) that removes the pending entry and refunds the burned/locked tokens to the original sender.

Without one of these mechanisms, any transfer to an ETH-rejecting contract address results in irrecoverable fund loss.

---

### Proof of Concept

1. User holds wrapped-ETH on NEAR and calls `ft_transfer_call` targeting the NEAR bridge, with `recipient = OmniAddress::Eth(<GnosisSafe address>)` where the Safe has no `receive()`.
2. `init_transfer_internal` burns the wrapped-ETH tokens and stores the `TransferMessage` in `pending_transfers`. Returns `U128(0)` — no refund.
3. MPC signs the transfer; a relayer calls `finTransfer` on EVM with `payload.tokenAddress == address(0)` and `payload.recipient = <GnosisSafe address>`.
4. `payload.recipient.call{value: payload.amount}("")` returns `success = false`.
5. `revert FailedToSendEther()` rolls back the transaction, including `completedTransfers[nonce] = true`.
6. Every subsequent relay attempt produces the same revert.
7. The wrapped-ETH is permanently burned on NEAR; no recovery path exists.

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

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
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

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
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
