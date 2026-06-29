### Title
Blacklisted ERC20 Recipient Permanently Freezes Bridged Funds in `finTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

When a user initiates a NEAR → EVM transfer specifying a blacklisted ERC20 address (e.g., a USDC-blacklisted address) as the recipient, the tokens are burned/locked on NEAR but `finTransfer` on the EVM side will always revert. Because the recipient is immutably encoded in the MPC-signed payload and no cancellation or redirect mechanism exists, the bridged funds are permanently frozen.

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` handles the final delivery of tokens to the recipient. For native ERC20 tokens (e.g., USDC on Arbitrum, Base, or Polygon), it calls:

```solidity
IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
```

The `payload.recipient` is an EVM address supplied by the user at `initTransfer` time on NEAR. It is Borsh-encoded and hashed as part of the MPC signature payload:

```solidity
Borsh.encodeAddress(payload.recipient),
```

The MPC signature covers the full payload including the recipient. There is no mechanism to change the recipient after signing, and no admin path to redirect or cancel a stuck transfer.

On the NEAR side, `sign_transfer_callback` removes the transfer from `pending_transfers` only when `fee.is_zero()`, and only upon successful MPC signing — not upon `finTransfer` failure on the destination chain. The tokens are burned or locked on NEAR at `init_transfer_internal` time and are never restored if `finTransfer` permanently fails.

If the recipient is blacklisted in the ERC20 token contract (e.g., USDC's `Blacklistable` modifier), `safeTransfer` reverts on every attempt. The nonce is marked used before the transfer (`completedTransfers[payload.destinationNonce] = true`), but since the whole EVM transaction reverts, the nonce is not permanently consumed — however, every retry with the same signed payload will fail identically. There is no alternative payload the relayer can submit.

---

### Impact Explanation

Bridged funds are permanently frozen:

- Tokens are burned or locked on NEAR at initiation.
- `finTransfer` on the EVM destination chain reverts on every attempt due to the blacklisted recipient.
- No mechanism exists to redirect the transfer to a different recipient or to refund the source-chain tokens.
- The `pending_transfers` entry on NEAR may be removed after signing (zero-fee case), but the underlying token balance is never restored.

This constitutes **permanent loss/freezing of bridged funds**, matching the Critical impact scope.

---

### Likelihood Explanation

USDC is an officially supported token on Arbitrum, Base, and Polygon — all supported EVM chains. A user's address can be blacklisted:

1. **Before initiation**: User accidentally specifies a known blacklisted address as recipient.
2. **After initiation but before finalization**: User's address is blacklisted by Circle between the time tokens are locked on NEAR and the time `finTransfer` is submitted on EVM. This window can be hours or days depending on relayer latency.

Both scenarios are realistic and require no privileged access — any bridge user can trigger this by specifying any EVM address as recipient.

---

### Recommendation

1. **On the EVM side**: Before calling `safeTransfer`, check whether the recipient is blacklisted (e.g., call `IUSDC(tokenAddress).isBlacklisted(payload.recipient)`). If blacklisted, send tokens to a recoverable escrow or revert with a specific error that allows the relayer to handle the case without consuming the nonce permanently.

2. **On the NEAR side**: Introduce a cancellation/refund path for `pending_transfers` entries that have been signed but whose `finTransfer` has permanently failed on the destination chain. This requires a proof-of-failure mechanism or a timeout-based admin recovery.

3. **Alternatively**: Allow the MPC to re-sign a corrected payload with a different recipient if the original recipient is provably blacklisted, subject to user authorization.

---

### Proof of Concept

1. User calls `ft_transfer_call` on NEAR with `recipient = OmniAddress::Eth(blacklisted_usdc_address)`.
2. `init_transfer_internal` burns/locks the tokens and stores the `TransferMessage` in `pending_transfers`. [1](#0-0) 
3. Relayer calls `sign_transfer`; NEAR MPC signs the `TransferMessagePayload` including `recipient: blacklisted_usdc_address`. [2](#0-1) 
4. Relayer submits `finTransfer` on EVM. The contract reaches the `safeTransfer` branch for native ERC20: [3](#0-2) 
5. USDC's `transfer` reverts with `"Blacklistable: account is blacklisted"`. The entire EVM transaction reverts.
6. Every subsequent retry with the same signed payload fails identically. No alternative payload can pass signature verification because `payload.recipient` is part of the signed hash: [4](#0-3) 
7. On NEAR, `sign_transfer_callback` removes the transfer from `pending_transfers` (zero-fee case) but does **not** restore the burned/locked tokens: [5](#0-4) 
8. Funds are permanently frozen with no recovery path.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L298-312)
```text
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
