### Title
Any Trusted Relayer Can Redirect Fee Recipient in `sign_transfer`, Stealing Relayer Fees - (File: near/omni-bridge/src/lib.rs)

---

### Summary

`sign_transfer` accepts a caller-controlled `fee_recipient` parameter with no validation that it matches the caller or any stored value. Any trusted relayer can call `sign_transfer` on any pending transfer and embed an arbitrary `fee_recipient` into the MPC-signed payload, then submit that signature to the destination chain and claim the fee on NEAR — stealing it from the legitimate relayer who was meant to service the transfer.

---

### Finding Description

`sign_transfer` in `near/omni-bridge/src/lib.rs` is decorated `#[trusted_relayer]` and accepts three caller-supplied arguments: `transfer_id`, `fee_recipient: Option<AccountId>`, and `fee: &Option<Fee>`. [1](#0-0) 

The `fee_recipient` value is taken verbatim from the caller and embedded into the `TransferMessagePayload` that is sent to the MPC signer: [2](#0-1) 

There is **no check** that `fee_recipient` equals `env::predecessor_account_id()` or any value stored in the transfer message. The contract only validates the `fee` amount (and only when `fee` is `Some`): [3](#0-2) 

After the MPC signs the payload, `sign_transfer_callback` emits a `SignTransferEvent` containing the full signed payload (including the attacker-chosen `fee_recipient`). The transfer message is only removed when `fee.is_zero()`; for non-zero-fee transfers it remains in storage, meaning multiple relayers can call `sign_transfer` on the same transfer: [4](#0-3) 

On the destination chain (e.g., EVM `OmniBridge.sol`), `finTransfer` verifies the MPC signature over the full borsh-encoded payload — which includes `fee_recipient` — and emits a `FinTransfer` event: [5](#0-4) 

Back on NEAR, `claim_fee_callback` verifies that the `fee_recipient` in the on-chain proof matches `predecessor_account_id`: [6](#0-5) 

Because the `fee_recipient` in the proof is whatever the attacker embedded at signing time, the attacker satisfies this check trivially.

---

### Impact Explanation

A malicious trusted relayer can:

1. Monitor NEAR for any pending `TransferMessage` with a non-zero fee.
2. Call `sign_transfer(transfer_id, Some(attacker_account), Some(stored_fee))` before the legitimate relayer does.
3. Receive an MPC signature over a payload with `fee_recipient = attacker_account`.
4. Submit this signature to the destination chain via `finTransfer`, completing the user's transfer.
5. Generate a proof of the resulting `FinTransfer` event and call `claim_fee` on NEAR.
6. Receive the full relayer fee.

The user's transfer completes correctly (recipient and amount are taken from the stored transfer message, not from the caller), but the legitimate relayer who was meant to service the transfer receives nothing. The fee — which is part of the user's locked/burned tokens — is mis-accounted to the attacker. For transfers with non-zero fees, the transfer message persists after signing, so the window of opportunity is not limited to a single block.

---

### Likelihood Explanation

Becoming a trusted relayer requires only staking the configured amount and waiting the waiting period — no admin approval or privileged access is needed: [7](#0-6) 

Any economically motivated actor can stake, become a trusted relayer, and systematically front-run every `sign_transfer` call to capture all relayer fees across the bridge. The attack is fully on-chain, requires no off-chain coordination, and is profitable at scale.

---

### Recommendation

Bind `fee_recipient` to the caller. Replace the caller-supplied parameter with `env::predecessor_account_id()` inside `sign_transfer`, or add an explicit check:

```rust
if let Some(ref recipient) = fee_recipient {
    require!(
        recipient == &env::predecessor_account_id(),
        BridgeError::InvalidFeeRecipient.as_ref()
    );
}
```

This mirrors the fix described in the reference report: localising the callback/recipient to the requester so that no other party can inject an arbitrary address.

---

### Proof of Concept

```
1. Legitimate relayer R1 observes TransferMessage {transfer_id: T, fee: 100, ...} on NEAR.
2. Malicious trusted relayer R2 calls:
       sign_transfer(T, Some("r2.near"), Some(Fee{fee:100,...}))
   before R1 can act.
3. MPC signs payload: {transfer_id:T, recipient:<user>, fee_recipient:"r2.near", amount:X, ...}
4. R2 submits the signed payload to OmniBridge.sol via finTransfer().
   - completedTransfers[destinationNonce] = true
   - Tokens released to the user's recipient address ✓
   - FinTransfer event emitted with fee_recipient="r2.near"
5. R2 generates an EVM Merkle proof of the FinTransfer event.
6. R2 calls claim_fee on NEAR with this proof.
   - claim_fee_callback: fee_recipient == "r2.near" == predecessor_account_id ✓
   - R2 receives 100 tokens.
7. R1 attempts sign_transfer or claim_fee — both fail or yield nothing.
   The fee is permanently diverted to R2.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-506)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-313)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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

**File:** near/omni-tests/src/relayer_staking.rs (L100-110)
```rust
        let applicant = env.create_funded_account("applicant", 2000).await?;

        // Apply
        let result = applicant
            .call(env.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_near(1000))
            .max_gas()
            .transact()
            .await?;
        result.into_result()?;

```
