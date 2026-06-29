Now I have all the information needed to make a determination. Let me trace the full attack path through the code.

### Title
Unrestricted `fee_recipient` in `sign_transfer` Allows Trusted Relayer to Steal Transfer Fees — (`near/omni-bridge/src/lib.rs`)

### Summary

`sign_transfer` accepts a caller-controlled `fee_recipient` parameter with no validation against any stored value, and for non-zero-fee transfers the transfer is never removed from `pending_transfers` after signing. A malicious trusted relayer can therefore call `sign_transfer` multiple times for the same `transfer_id` with different `fee_recipient` values, obtain multiple distinct valid MPC signatures, and submit the one that routes the fee to an attacker-controlled address on the destination chain.

### Finding Description

`sign_transfer` constructs a `TransferMessagePayload` that includes the caller-supplied `fee_recipient` and sends it to the MPC signer: [1](#0-0) 

The only fee-related validation is that the provided `fee` amount matches the stored transfer fee: [2](#0-1) 

There is no check that `fee_recipient` matches any stored or previously committed value.

In `sign_transfer_callback`, the transfer is removed from `pending_transfers` **only** when `fee.is_zero()`: [3](#0-2) 

For any transfer with a non-zero fee, the transfer record persists in `pending_transfers` indefinitely (until `claim_fee` is called), so `sign_transfer` can be called again for the same `transfer_id` with a different `fee_recipient`, producing a second valid MPC signature over a different payload hash.

On the EVM side, `finTransfer` verifies the MPC signature over the borsh-encoded payload (which includes `feeRecipient`) and marks the `destinationNonce` as consumed: [4](#0-3) 

The relayer chooses which of the two valid signatures to submit. The submitted `feeRecipient` is emitted in the `FinTransfer` event and later used by `claim_fee_callback` on NEAR to authorize fee disbursement: [5](#0-4) 

### Impact Explanation

A malicious trusted relayer can redirect 100% of the token fee (and native fee) for any non-zero-fee transfer to an attacker-controlled NEAR account. The principal amount and recipient are unaffected, but the fee escrow is mis-accounted: the legitimate relayer receives nothing, and the attacker claims the fee via `claim_fee`. This constitutes fee mis-accounting / escrow mis-accounting under the Critical impact scope.

### Likelihood Explanation

Any account that has staked the required NEAR and waited through the activation period qualifies as a trusted relayer. The attack requires no additional privilege beyond that. The call sequence is straightforward and requires no race condition or front-running — the attacker simply calls `sign_transfer` twice before submitting to the destination chain. The only cost is the MPC signing deposit paid twice.

### Recommendation

1. **Remove the transfer from `pending_transfers` after the first successful MPC signing**, regardless of whether the fee is zero. This prevents a second call from obtaining a second signature.
2. Alternatively, **store the `fee_recipient` in the `TransferMessage` at initiation time** (or at first signing) and validate that subsequent calls to `sign_transfer` supply the same value.
3. As a defense-in-depth measure, add an "in-flight signing" flag that is set before the MPC call and cleared in the callback, preventing concurrent or repeated signing for the same transfer.

### Proof of Concept

```
// 1. User initiates transfer with fee = 100 tokens
//    pending_transfers[transfer_id] = TransferMessage { fee: 100, ... }

// 2. Malicious relayer: first call
sign_transfer(transfer_id, fee_recipient = Some("attacker.near"), fee = Some(Fee{fee:100,...}))
// → MPC signs payload_A = hash(... fee_recipient="attacker.near" ...)
// → sign_transfer_callback: fee.is_zero() == false → transfer NOT removed
// → SignTransferEvent { sig_A, payload_A } emitted

// 3. Malicious relayer: second call (transfer still in pending_transfers)
sign_transfer(transfer_id, fee_recipient = Some("legitimate.near"), fee = Some(Fee{fee:100,...}))
// → MPC signs payload_B = hash(... fee_recipient="legitimate.near" ...)
// → SignTransferEvent { sig_B, payload_B } emitted
// Both sig_A and sig_B are valid MPC signatures; same destination_nonce

// 4. Relayer submits sig_A + payload_A to EVM finTransfer
//    completedTransfers[destination_nonce] = true
//    FinTransfer event emitted with feeRecipient = "attacker.near"

// 5. Attacker calls claim_fee on NEAR with EVM proof
//    claim_fee_callback: fee_recipient ("attacker.near") == predecessor → passes
//    Attacker receives 100 tokens; legitimate relayer receives nothing
```

Assert: two distinct `SignTransferEvent`s are emitted with the same `destination_nonce` but different `fee_recipient` fields, confirming the invariant "only one valid signed payload per transfer" is broken. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L447-521)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

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
            )
    }
```

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L1079-1086)
```rust
        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-313)
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
```
