### Title
Unauthorized `fee_recipient` Specification in `sign_transfer` Allows Any Trusted Relayer to Steal Transfer Fees — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`sign_transfer` accepts a caller-controlled `fee_recipient` parameter with no validation that the caller has any relationship to the pending transfer. Because the transfer message remains in storage when `fee > 0`, any trusted relayer can call `sign_transfer` on any pending transfer and embed their own account as `fee_recipient` in the MPC-signed payload. The destination chain's nonce mechanism means only one signature can ever be used; whichever relayer's signature is submitted first on the destination chain wins the fee. This is the direct analog of the external report's "first offer wins" pattern: the bridge blindly signs whatever `fee_recipient` the first caller supplies, with no sender authentication.

---

### Finding Description

`sign_transfer` in `near/omni-bridge/src/lib.rs` is decorated `#[trusted_relayer]` but imposes no constraint on who the `fee_recipient` may be:

```rust
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // ← fully caller-controlled
    fee: &Option<Fee>,
) -> Promise {
    let transfer_message = self.get_transfer_message(transfer_id);
    // ... no check that caller == intended fee recipient
    let transfer_payload = TransferMessagePayload {
        ...
        fee_recipient,   // ← attacker's account embedded here
        ...
    };
    // MPC signs this payload
``` [1](#0-0) 

The callback only removes the transfer message when `fee.is_zero()`:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
``` [2](#0-1) 

For any transfer with `fee > 0`, the transfer message persists in storage and `sign_transfer` can be called repeatedly by different trusted relayers, each producing a distinct MPC-signed payload with a different `fee_recipient` but the same `destination_nonce`.

On the EVM destination, `finTransfer` marks the nonce used on the first call and rejects all subsequent ones:

```solidity
if (completedTransfers[payload.destinationNonce]) {
    revert NonceAlreadyUsed(payload.destinationNonce);
}
completedTransfers[payload.destinationNonce] = true;
``` [3](#0-2) 

The `feeRecipient` field is part of the Borsh-encoded payload that the MPC signature covers, so the destination chain pays the fee to whoever is named in the winning signature: [4](#0-3) 

The same pattern holds on Starknet (`fin_transfer` verifies the borsh signature which includes `fee_recipient`) and Solana (`FinalizeTransferPayload.fee_recipient` is part of the signed message): [5](#0-4) [6](#0-5) 

---

### Impact Explanation

A malicious trusted relayer can steal the entire token fee (and native fee) from any pending NEAR-outbound transfer. The user's principal transfer completes correctly (recipient receives `amount − fee`), but the fee is redirected from the legitimate relayer to the attacker. This is fee mis-accounting that directly changes protocol-level balances: the legitimate relayer's expected income is zero, and the attacker gains it without having performed the work.

---

### Likelihood Explanation

Becoming a trusted relayer requires staking 1 000 NEAR and waiting 7 days (the default `waiting_period_ns`): [7](#0-6) 

This is a meaningful but not prohibitive barrier. Once trusted, the attacker can target every pending transfer with a non-zero fee indefinitely. The attack requires no special knowledge beyond observing on-chain events (the `InitTransferEvent` is public), and no front-running of the user — only of the legitimate relayer's `sign_transfer` call. Because `sign_transfer` is a separate step from `ft_on_transfer`, there is always a window between transfer creation and signing.

---

### Recommendation

1. **Bind `fee_recipient` to the caller**: Require `fee_recipient == env::predecessor_account_id()` (or derive it from the caller), so only the relayer who actually calls `sign_transfer` can name themselves as recipient, and no other relayer can override it.
2. **Alternatively, record the intended fee recipient at transfer creation time** (e.g., in `TransferMessage`) and enforce it in `sign_transfer`, rejecting any caller-supplied value that differs.
3. **Remove the transfer from storage on the first successful `sign_transfer` call** (regardless of fee), preventing repeated signing attempts on the same transfer.

---

### Proof of Concept

```
1. User calls ft_transfer_call → ft_on_transfer → init_transfer.
   Transfer stored: { transfer_id: T, fee: 100, ... }
   Event emitted: InitTransferEvent { transfer_id: T, ... }

2. Legitimate relayer R calls sign_transfer(T, fee_recipient=R, fee=...).
   MPC begins signing payload_R = { ..., fee_recipient: R, destination_nonce: N }.

3. Attacker A (also a trusted relayer) observes the InitTransferEvent.
   A calls sign_transfer(T, fee_recipient=A, fee=...) in the same or next block.
   MPC begins signing payload_A = { ..., fee_recipient: A, destination_nonce: N }.
   (Transfer message still in storage because fee > 0.)

4. Both MPC signing requests complete. Two valid signatures exist:
   sig_R over payload_R  (fee → R)
   sig_A over payload_A  (fee → A)

5. A submits finTransfer(sig_A, payload_A) to EVM first.
   completedTransfers[N] = true.
   Recipient receives amount. Fee is paid to A.

6. R attempts finTransfer(sig_R, payload_R).
   Reverts: NonceAlreadyUsed(N).
   R receives nothing.
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-520)
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

**File:** starknet/src/omni_bridge.cairo (L247-254)
```text
            assert(
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );
```

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L11-16)
```rust
pub struct FinalizeTransferPayload {
    pub destination_nonce: u64,
    pub transfer_id: TransferId,
    pub amount: u128,
    pub fee_recipient: Option<String>,
}
```

**File:** near/omni-tests/src/relayer_staking.rs (L507-509)
```rust
        let default_stake = (1_000u128 * 10u128.pow(24)).to_string();
        assert_eq!(config["stake_required"], json!(default_stake));
        assert_eq!(config["waiting_period_ns"], json!(U64(604_800_000_000_000)));
```
