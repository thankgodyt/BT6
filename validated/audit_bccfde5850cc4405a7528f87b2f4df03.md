### Title
Missing Zero-Address Validation for EVM Recipient Causes Permanent Freezing of Bridged ERC20 Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
When a user initiates a NEAR→EVM bridge transfer specifying `address(0)` as the EVM recipient, the NEAR bridge signs the payload without validating the recipient address. The EVM `finTransfer()` then attempts `safeTransfer` to `address(0)`, which reverts for standard ERC20 tokens. Because the MPC signature is cryptographically bound to `recipient = address(0)`, no valid finalization is ever possible, and the user's tokens — already burned or locked on NEAR — are permanently frozen with no recovery path.

### Finding Description
In `OmniBridge.sol`, `finTransfer()` processes the final leg of a NEAR→EVM transfer. The nonce is marked completed at line 287 before the token transfer. For standard ERC20 tokens (the `else` branch at lines 350–354), `IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount)` is called. OpenZeppelin's `SafeERC20.safeTransfer` internally calls the ERC20 `transfer`, which reverts when `to == address(0)` per the standard implementation. [1](#0-0) [2](#0-1) 

The `payload.recipient` is part of the MPC-signed `TransferMessagePayload`. On the NEAR side, `sign_transfer()` constructs the payload with `recipient: transfer_message.recipient` and passes it directly to the MPC signer without any zero-address check. [3](#0-2) [4](#0-3) 

Once the MPC signature is produced and emitted, the payload is immutable. The `sign_transfer_callback` removes the transfer message only when `fee.is_zero()`, but in either case the tokens are already burned or locked on NEAR with no refund mechanism. [5](#0-4) 

The same issue applies to bridge tokens: `IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount)` also reverts for `address(0)` in standard ERC20-based mint implementations. [6](#0-5) 

### Impact Explanation
Permanent freezing of bridged ERC20 funds. The user's tokens are burned or locked on NEAR at transfer initiation. Because the MPC-signed payload fixes `recipient = address(0)`, every subsequent `finTransfer` call with that payload reverts. No admin, DAO, or relayer function exists to update the recipient of a committed transfer message or to refund the burned tokens. The funds are irrecoverably lost.

### Likelihood Explanation
Low but realistic. A user with a buggy script, uninitialized address variable, or misconfigured frontend can accidentally submit `address(0)` as the EVM recipient. The NEAR bridge performs no validation of the EVM recipient address before committing the transfer and requesting an MPC signature, making this a silent, unrecoverable failure mode.

### Recommendation
1. In `OmniBridge.sol` `finTransfer()`, add an explicit guard before any token dispatch: `require(payload.recipient != address(0), "InvalidRecipient")`.
2. In `near/omni-bridge/src/lib.rs` `sign_transfer()`, validate that EVM-family recipients (`OmniAddress::Eth`, `OmniAddress::Arb`, etc.) are not the zero address before requesting the MPC signature.

### Proof of Concept
1. User calls `ft_on_transfer` on NEAR specifying `recipient = "eth:0x0000000000000000000000000000000000000000"`. Tokens are burned on NEAR.
2. A relayer calls `sign_transfer(transfer_id, fee_recipient, fee)`. NEAR constructs `TransferMessagePayload { recipient: OmniAddress::Eth(H160::ZERO), ... }` and requests MPC signature — no zero-address check occurs.
3. MPC signs and emits the signature. The signed payload is now immutable.
4. Relayer calls `finTransfer(signature, payload)` on EVM with a standard ERC20 `tokenAddress`.
5. Execution reaches `IERC20(payload.tokenAddress).safeTransfer(address(0), payload.amount)` — reverts with `ERC20: transfer to the zero address`.
6. The transaction reverts; the nonce is not consumed. But the MPC signature is fixed to `recipient = address(0)`, so every future `finTransfer` attempt with this payload also reverts.
7. The user's tokens remain burned on NEAR with no recovery path.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-349)
```text
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
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

**File:** near/omni-bridge/src/lib.rs (L508-520)
```rust
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
            )
```

**File:** near/omni-bridge/src/lib.rs (L655-667)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
```
