### Title
Permanent Freezing of Bridged Funds When EVM Recipient Cannot Receive Native ETH or ERC-1155 Tokens in `finTransfer` - (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.sol::finTransfer` hard-reverts when the EVM recipient cannot receive native ETH (or when `safeTransferFrom` for ERC-1155 reverts). Because the entire transaction reverts, the `completedTransfers` nonce is never consumed, so the relayer can retry — but will always fail. Meanwhile, the user's tokens were already burned/locked on NEAR when the transfer was initiated, and there is no cancel or redirect mechanism on NEAR to recover them. The funds are permanently frozen.

### Finding Description

**NEAR → EVM transfer flow:**

1. User calls `ft_on_transfer` on NEAR → `init_transfer_internal` burns/locks tokens and records the transfer in `pending_transfers`.
2. A relayer calls `sign_transfer` to obtain an MPC signature over the `TransferMessagePayload`.
3. The relayer calls `finTransfer` on `OmniBridge.sol` with the signature and payload.

Inside `finTransfer`, the nonce is marked used **before** the external call (correct reentrancy practice), but if the external call reverts, the entire transaction reverts and the nonce is **not** consumed:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287 — reverted on failure
// ...
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();           // line 322 — reverts whole tx
}
```

The same pattern applies to ERC-1155 transfers:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,   // if recipient doesn't implement onERC1155Received → revert
    multiToken.tokenId,
    payload.amount,
    ""
);
```

If the recipient is a contract that permanently rejects ETH (no `receive()`/`fallback()`) or does not implement `IERC1155Receiver`, every `finTransfer` attempt will revert. The nonce is never consumed, so the transfer remains in `pending_transfers` on NEAR indefinitely. The tokens burned/locked in `init_transfer_internal` are irrecoverable because:

- There is no `cancel_transfer` function on NEAR.
- `update_transfer_fee` only updates the fee, not the recipient.
- `claim_fee` requires proof of successful EVM finalization, which can never happen.
- The MPC signature is already bound to the original `recipient` field in the Borsh-encoded payload; a new signature for a different recipient would require a new `sign_transfer` call, but the transfer nonce is already consumed on NEAR.

### Impact Explanation

Permanent freezing of bridged funds. Tokens burned/locked on NEAR can never be recovered if the EVM recipient address is a contract that cannot receive native ETH or ERC-1155 tokens. This matches the Critical impact category: *permanent freezing of bridged funds across NEAR and EVM flows*.

### Likelihood Explanation

Realistic. Users commonly specify smart contract addresses as recipients — multisigs, DAO treasuries, smart contract wallets, or protocol contracts — many of which lack a `receive()` function or `IERC1155Receiver` implementation. A single mistaken recipient address results in permanent loss with no on-chain remedy.

### Recommendation

Add a pull-payment / redirect mechanism analogous to the Foundation report's `withdrawTo`. Concretely:

1. **On EVM**: Instead of reverting on failed ETH send, record the amount in a `pendingWithdrawals[recipient]` mapping and emit an event. Add a `withdrawTo(address to)` function that lets the original recipient redirect their pending ETH to any address they control.
2. **On NEAR**: Add a `cancel_transfer` function (DAO-gated or sender-gated after a timeout) that removes the entry from `pending_transfers`, re-mints/unlocks the tokens to the original sender, and invalidates the destination nonce so the MPC signature cannot be replayed.

### Proof of Concept

1. User holds 1 NEAR-side token and calls `ft_on_transfer` targeting a NEAR → ETH transfer with `recipient = 0xDeadContract` (a contract with no `receive()`).
2. `init_transfer_internal` burns the token and records the transfer. [1](#0-0) 
3. Relayer calls `sign_transfer`; MPC signs the payload binding `recipient = 0xDeadContract`. [2](#0-1) 
4. Relayer calls `finTransfer` on EVM. `completedTransfers[nonce] = true` is set, then the ETH send fails → `revert FailedToSendEther()` → entire tx reverts → nonce not consumed. [3](#0-2) 
5. Every subsequent `finTransfer` attempt reverts identically. The transfer remains in `pending_transfers` on NEAR forever. The burned token is unrecoverable. No cancel or redirect function exists. [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L491-519)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L287-322)
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

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```
