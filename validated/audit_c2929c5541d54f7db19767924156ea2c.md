### Title
`sign_transfer` Does Not Remove or Lock the Pending Transfer Before the Async MPC Signing Call, Enabling Multiple Valid Signatures Per Transfer - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`sign_transfer` reads the transfer from `pending_transfers` but does not remove or mark it as "in-flight" before dispatching the async MPC signing cross-contract call. Because NEAR processes multiple transactions in the same block before any callback receipt fires, a trusted relayer can submit two `sign_transfer` calls for the same `transfer_id` in the same block, causing the MPC signer to produce two independent, valid signatures for the same transfer — each potentially carrying a different `fee_recipient`.

### Finding Description

`sign_transfer` reads the transfer via `get_transfer_message` (a read-only lookup) and immediately dispatches the MPC signing call without removing or locking the entry in `pending_transfers`: [1](#0-0) 

The callback `sign_transfer_callback` only removes the transfer when `fee.is_zero()`: [2](#0-1) 

For **non-zero fee transfers** the entry is never removed by `sign_transfer_callback` at all — it stays in `pending_transfers` until `claim_fee` is called — so unlimited signing calls are possible at any time.

For **zero-fee transfers** the entry is removed only after the first callback fires. Because NEAR's receipt model processes cross-contract callbacks in a subsequent block, two `sign_transfer` transactions submitted in the same block both read the still-present entry and both enqueue MPC signing receipts before either callback executes. The first callback removes the entry; the second callback's removal fails silently — but both MPC signatures have already been produced and emitted as `SignTransferEvent` log entries.

The `fee_recipient` field is a caller-supplied parameter that is embedded in the signed `TransferMessagePayload`: [3](#0-2) 

Two calls with different `fee_recipient` values produce two cryptographically distinct, valid payloads and two valid MPC signatures.

### Impact Explanation

A malicious trusted relayer can:

1. Submit `sign_transfer(transfer_id, fee_recipient=attacker_account, fee=F)` and `sign_transfer(transfer_id, fee_recipient=legitimate_relayer, fee=F)` in the same block.
2. Obtain two valid MPC signatures — one directing the fee to the attacker, one to the legitimate relayer.
3. Submit the attacker-favoring signature to the destination chain, stealing the fee that should have gone to the legitimate relayer.

For zero-fee transfers, two valid signatures for the same `destination_nonce` are produced. If the destination chain's nonce/replay protection is not airtight, both could be submitted to release funds twice — a direct double-spend of bridged assets. Even where the destination chain does enforce nonce uniqueness, the attacker holds a second valid signature that can be used opportunistically (e.g., if the nonce tracking is per-contract and the token is deployed on multiple chains sharing the same nonce space).

The `pending_transfers` map is the sole on-chain guard against re-signing; once the transfer is removed (zero-fee path) or never removed (non-zero fee path), there is no other mechanism preventing repeated MPC signing of the same transfer.

### Likelihood Explanation

Any account that stakes the required amount (default 1 000 NEAR) and waits the waiting period becomes a trusted relayer and can call `sign_transfer`. The `#[trusted_relayer]` macro is the only gate: [4](#0-3) 

Submitting two transactions in the same NEAR block is a standard operation requiring no special tooling. The attack is deterministic and requires no front-running, no validator collusion, and no external dependency failure.

### Recommendation

Remove the transfer from `pending_transfers` (or insert a "signing-in-progress" sentinel) **before** dispatching the MPC cross-contract call, analogous to how `add_fin_transfer` uses an atomic insert-or-panic pattern: [5](#0-4) 

If re-signing must be supported (e.g., for fee updates), re-insert the transfer in the callback on failure, mirroring the pattern used in the UTXO connector callback.

### Proof of Concept

```
Block N:
  TX-A: trusted_relayer calls sign_transfer(transfer_id=T, fee_recipient=ATTACKER, fee=F)
        → get_transfer_message(T) succeeds (entry present)
        → enqueues MPC signing receipt R-A
  TX-B: trusted_relayer calls sign_transfer(transfer_id=T, fee_recipient=LEGITIMATE, fee=F)
        → get_transfer_message(T) succeeds (entry still present; TX-A did not remove it)
        → enqueues MPC signing receipt R-B

Block N+1:
  R-A fires → sign_transfer_callback: fee != 0, entry NOT removed; emits SignTransferEvent(sig=S-A, fee_recipient=ATTACKER)
  R-B fires → sign_transfer_callback: fee != 0, entry NOT removed; emits SignTransferEvent(sig=S-B, fee_recipient=LEGITIMATE)

Attacker submits (payload-A, S-A) to destination chain → fee credited to ATTACKER.
Signature S-B is discarded or held for future use.
```

For zero-fee transfers, replace `fee=F` with `fee=0`; the first callback removes the entry, the second callback's removal panics (but S-B was already produced and emitted before the panic).

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-521)
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

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
