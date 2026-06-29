### Title
Blocklisted ERC-20 recipient permanently freezes bridged funds in `finTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer` uses a Push pattern to deliver tokens to the recipient embedded in the MPC-signed payload. For native ERC-20 tokens (e.g., USDC, USDT) that implement an admin-controlled address blocklist, a transfer whose `payload.recipient` is on the blocklist will always revert. Because the NEAR side burns/locks the user's tokens at `init_transfer` time and provides no timeout-based refund path, the funds are permanently frozen.

---

### Finding Description

`OmniBridge.finTransfer` handles native (non-bridge, non-custom-minter) ERC-20 tokens with a direct push:

```solidity
} else {
    IERC20(payload.tokenAddress).safeTransfer(
        payload.recipient,
        payload.amount
    );
}
``` [1](#0-0) 

The `payload.recipient` is the EVM address that was committed to by the user at `init_transfer` time on NEAR and is cryptographically bound in the MPC signature verified just above:

```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [2](#0-1) 

Because the recipient is fixed in the signed payload, no alternative address can be substituted. If `payload.recipient` is on the USDC/USDT blocklist, `safeTransfer` reverts, the entire transaction reverts (including the `completedTransfers[payload.destinationNonce] = true` write at line 287), and the nonce is never consumed — but every future attempt to finalize the same transfer will also revert for the same reason. [3](#0-2) 

On the NEAR side, the user's tokens were already burned or locked inside `init_transfer_internal` before the MPC signature was ever requested:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
``` [4](#0-3) 

The transfer record sits in `pending_transfers` indefinitely. There is no timeout, no user-initiated cancellation, and no cross-chain refund path visible in the contract. The funds are unrecoverable. [5](#0-4) 

---

### Impact Explanation

**Critical.** Any user who bridges a blocklist-capable ERC-20 token (USDC, USDT) to an EVM address that is subsequently (or already) on the token's blocklist will have their NEAR-side tokens permanently burned/locked with no recovery. This constitutes permanent freezing of bridged funds.

---

### Likelihood Explanation

**Low.** Two conditions must coincide: (1) the bridged token implements an admin-controlled blocklist (USDC and USDT do), and (2) the recipient EVM address is on that blocklist at finalization time. Both conditions are realistic — USDC/USDT are among the most commonly bridged assets, and blocklisting of addresses does occur in practice (e.g., OFAC-sanctioned addresses).

---

### Recommendation

Replace the Push pattern with a Pull pattern for native ERC-20 delivery in `finTransfer`. Instead of calling `safeTransfer` directly to `payload.recipient`, record the claimable balance in a mapping and expose a separate `claimTokens()` function that the recipient calls to withdraw. This decouples finalization (nonce consumption, event emission) from token delivery, so a blocklisted recipient cannot prevent the protocol from marking the transfer as complete, and the recipient can claim once they are removed from the blocklist — or an alternative recovery path can be provided.

---

### Proof of Concept

1. Alice holds USDC on NEAR and calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer` with `recipient = 0xAliceEVM`. Her USDC is burned on NEAR; the transfer is stored in `pending_transfers`. [6](#0-5) 

2. The MPC signs a `TransferMessagePayload` binding `recipient = 0xAliceEVM` and `tokenAddress = USDC`. [7](#0-6) 

3. Before or after step 2, USDC's admin adds `0xAliceEVM` to the blocklist.

4. A relayer calls `OmniBridge.finTransfer(signatureData, payload)`. Signature verification passes. The call reaches:
   ```solidity
   IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
   ```
   USDC's `transfer` reverts because `0xAliceEVM` is blocklisted. The entire transaction reverts. [1](#0-0) 

5. Every subsequent `finTransfer` attempt reverts identically. Alice's USDC is permanently lost — burned on NEAR, undeliverable on EVM, with no refund mechanism.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-288)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** near/omni-bridge/src/lib.rs (L222-223)
```rust
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
    pub finalised_transfers: LookupSet<TransferId>,
```

**File:** near/omni-bridge/src/lib.rs (L491-500)
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
```

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
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
