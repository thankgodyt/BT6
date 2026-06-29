### Title
Any Trusted Relayer Can Redirect Transfer Fees to Themselves via Unconstrained `fee_recipient` in `sign_transfer` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `sign_transfer` function accepts a caller-supplied `fee_recipient` parameter that is embedded verbatim into the MPC-signed `TransferMessagePayload`. Because any account that has staked the required NEAR and passed the waiting period qualifies as a trusted relayer, a malicious trusted relayer can call `sign_transfer` for any pending transfer with `fee_recipient` set to their own account, obtain a valid MPC signature routing the fee to themselves, and submit it on the destination chain before the legitimate relayer does — permanently consuming the destination nonce and stealing the fee.

---

### Finding Description

`sign_transfer` is gated by `#[trusted_relayer]`, which allows any account that has self-staked the configured NEAR amount and survived the waiting period to call it. The function accepts `fee_recipient: Option<AccountId>` with no validation against any stored transfer state: [1](#0-0) 

The caller-supplied `fee_recipient` is placed directly into `TransferMessagePayload`: [2](#0-1) 

This payload is then hashed and sent to the MPC signer: [3](#0-2) 

The MPC signature covers the entire payload, including `fee_recipient`. On the EVM side, `finTransfer` Borsh-encodes `payload.feeRecipient` as part of the data it verifies against the MPC signature: [4](#0-3) 

Critically, `sign_transfer_callback` only removes the transfer message when the fee is zero: [5](#0-4) 

For any non-zero-fee transfer, the transfer message remains in `pending_transfers` after signing. This means multiple trusted relayers can each call `sign_transfer` for the same `transfer_id` with different `fee_recipient` values, each obtaining a distinct but cryptographically valid MPC signature. Whoever submits their signature first on the destination chain consumes the `destinationNonce`, making all other signatures permanently useless.

Becoming a trusted relayer is permissionless — any account can call `apply_for_trusted_relayer` with the required stake deposit and, after the waiting period, is automatically promoted: [6](#0-5) 

The stake is fully returned on voluntary resignation (`resign_trusted_relayer`), so the attacker's net cost is only gas.

---

### Impact Explanation

A malicious trusted relayer can steal the fee from any pending transfer. The user's transfer still completes (they receive `amount − fee` on the destination chain), but the legitimate relayer loses their fee revenue. Because the destination nonce is consumed by the attacker's submission, the legitimate relayer's subsequently obtained signature is permanently invalid. This constitutes fee mis-accounting that changes relayer and attacker balances on every targeted transfer.

---

### Likelihood Explanation

The barrier to entry is economic: the attacker must stake the configured NEAR amount and wait. However, since the stake is returned on resignation, the attacker's only real cost is gas. If the aggregate fees stolen across multiple transfers exceed gas costs — which is likely for any active bridge with non-trivial fee settings — the attack is profitable. The attacker can resign before the DAO detects and slashes them, recovering their stake. No privileged access, leaked keys, or external dependency failure is required.

---

### Recommendation

Store the `fee_recipient` inside the `TransferMessage` at initiation time (in `init_transfer`) so it is fixed and cannot be overridden by the signing relayer. Alternatively, validate the caller-supplied `fee_recipient` against a stored or derived value, or restrict `sign_transfer` so that only the transfer's original sender or a pre-registered relayer for that transfer can supply the `fee_recipient`.

---

### Proof of Concept

1. User calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer`, creating a pending transfer with `fee = 100 tokens`.
2. Legitimate relayer prepares to call `sign_transfer(transfer_id, fee_recipient = "relayer.near", fee = ...)`.
3. Malicious trusted relayer races ahead and calls `sign_transfer(transfer_id, fee_recipient = "attacker.near", fee = ...)`.
4. MPC network produces a valid signature over `TransferMessagePayload { ..., fee_recipient: Some("attacker.near"), ... }`.
5. Attacker submits this signature to EVM `finTransfer` → `destinationNonce` is marked used, fee is paid to `attacker.near`.
6. Legitimate relayer later obtains their own valid MPC signature (transfer message was not removed), but EVM reverts with `NonceAlreadyUsed` — their fee is permanently lost.

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-500)
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
```

**File:** near/omni-bridge/src/lib.rs (L502-521)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L655-668)
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
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-300)
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
```

**File:** near/omni-tests/src/environment.rs (L589-612)
```rust
    pub async fn setup_trusted_relayer(&self, relayer_id: AccountId) -> anyhow::Result<Account> {
        let relayer_account = self.create_account(relayer_id).await?;

        self.bridge_contract
            .call("set_relayer_config")
            .args_json(json!({
                "stake_required": "1",
                "waiting_period_ns": "0",
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        relayer_account
            .call(self.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_yoctonear(1))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        Ok(relayer_account)
    }
```
