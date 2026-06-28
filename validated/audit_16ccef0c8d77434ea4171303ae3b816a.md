### Title
Unconstrained `fee_recipient` in `sign_transfer` Allows Any Trusted Relayer to Steal Transfer Fees — (File: `near/omni-bridge/src/lib.rs`)

### Summary

`sign_transfer` accepts a caller-supplied `fee_recipient` parameter with no validation that it equals the caller's own account. Because the MPC signs whatever `fee_recipient` is embedded in the payload, any active trusted relayer can obtain a valid MPC signature naming themselves as fee recipient for a transfer they did not originate, finalize it on the destination chain first, and claim the full fee — stealing it from the legitimate relayer.

### Finding Description

`sign_transfer` is the NEAR-side entry point that requests an MPC signature for an outbound transfer. It is gated by `#[trusted_relayer]` but places no constraint on the `fee_recipient` argument:

```rust
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // ← no check against predecessor_account_id()
    fee: &Option<Fee>,
) -> Promise {
    let transfer_message = self.get_transfer_message(transfer_id);
    // ...
    let transfer_payload = TransferMessagePayload {
        // ...
        fee_recipient,          // ← embedded verbatim into the signed payload
        // ...
    };
    ext_signer::ext(self.mpc_signer.clone())
        .sign(SignRequest { payload, ... })
        .then(Self::ext(...).sign_transfer_callback(transfer_payload, &transfer_message.fee))
}
``` [1](#0-0) 

`sign_transfer_callback` only removes the transfer message when the fee is zero; for fee-bearing transfers the pending transfer record stays in place, meaning **multiple trusted relayers can each call `sign_transfer` for the same `transfer_id` with different `fee_recipient` values and each receive a distinct, valid MPC signature**:

```rust
pub fn sign_transfer_callback(...) {
    if let Ok(signature) = call_result {
        if fee.is_zero() {
            self.remove_transfer_message(message_payload.transfer_id); // only removed when fee == 0
        }
        env::log_str(&OmniBridgeEvent::SignTransferEvent { ... }.to_log_string());
    }
}
``` [2](#0-1) 

`claim_fee_callback` enforces `fee_recipient == predecessor_account_id`, but this check is against the `fee_recipient` that was baked into the MPC-signed payload and later emitted as an on-chain event on the destination chain — so whoever wins the race to finalize with their own `fee_recipient` passes this check:

```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
``` [3](#0-2) 

### Impact Explanation

A malicious trusted relayer (Relayer B) can:

1. Observe any pending transfer in `pending_transfers` (public on-chain state).
2. Call `sign_transfer(transfer_id, fee_recipient = B, fee)` — no validation prevents this.
3. Receive a valid MPC signature with `fee_recipient = B` embedded.
4. Submit the finalization transaction on the destination chain (EVM/Solana/Starknet) before the legitimate relayer, using their own signature.
5. Call `claim_fee` on NEAR with the resulting proof, passing the `fee_recipient == predecessor` check and receiving the full fee.

The legitimate relayer's signature (with `fee_recipient = A`) is rendered worthless because the destination chain's nonce/replay protection prevents a second finalization of the same transfer.

This is **fee mis-accounting**: the fee locked in the bridge escrow is paid to the wrong party. The `fee` and `native_fee` amounts can be substantial (set by the user at transfer initiation), making this economically significant. [4](#0-3) 

### Likelihood Explanation

Trusted relayer status is permissionlessly obtainable: any account can call `apply_for_trusted_relayer` with the required stake (default 1,000 NEAR) and wait out the waiting period (default ~7 days). No admin approval is required in the auto-promote path. [5](#0-4) [6](#0-5) 

Once active, the attacker does not need to front-run a NEAR transaction — they simply call `sign_transfer` for any pending transfer at any time (the transfer record is not locked or consumed by a prior `sign_transfer` call) and race to finalize on the destination chain, which is a much simpler operation than NEAR mempool front-running.

### Recommendation

Enforce that `fee_recipient` is bound to the caller's identity inside `sign_transfer`:

```rust
let effective_fee_recipient = fee_recipient
    .filter(|r| *r == env::predecessor_account_id())
    .or_else(|| Some(env::predecessor_account_id()));
```

Or, more simply, remove the `fee_recipient` parameter entirely and always derive it from `env::predecessor_account_id()`. This mirrors the pattern already used in `fin_transfer_callback` where `predecessor_account_id` is captured at call time and threaded through the callback chain. [7](#0-6) 

### Proof of Concept

1. User calls `ft_transfer_call` → `init_transfer` on NEAR, locking 10,000 tokens with `fee = 500`.
2. Legitimate Relayer A calls `sign_transfer(transfer_id, fee_recipient = A, fee)` → MPC returns `sig_A` with `fee_recipient = A`.
3. Malicious Relayer B (a separately staked trusted relayer) calls `sign_transfer(transfer_id, fee_recipient = B, fee)` → MPC returns `sig_B` with `fee_recipient = B`. This call succeeds because `sign_transfer` does not check `fee_recipient == predecessor_account_id()` and the transfer record is still present (fee ≠ 0 so `sign_transfer_callback` did not remove it).
4. Relayer B submits `finTransfer` on the EVM destination chain using `sig_B`, emitting a `FinTransfer` event with `fee_recipient = B`.
5. Relayer B calls `claim_fee` on NEAR with the EVM proof. `claim_fee_callback` reads `fee_recipient = B` from the proof, checks `B == predecessor_account_id()` (passes), and transfers 500 tokens to B.
6. Relayer A's `sig_A` is now useless — the destination chain nonce is consumed and `claim_fee` with A's proof would fail because the transfer message has already been removed. [8](#0-7)

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

**File:** near/omni-bridge/src/lib.rs (L687-695)
```rust
        main_promise.then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(attached_deposit)
                .with_static_gas(FIN_TRANSFER_CALLBACK_GAS)
                .fin_transfer_callback(
                    &args.storage_deposit_actions,
                    env::predecessor_account_id(),
                ),
        )
```

**File:** near/omni-bridge/src/lib.rs (L1075-1133)
```rust
        let Ok(ProverResult::FinTransfer(fin_transfer)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };

        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);

        if let Some(origin_transfer_id) = transfer_message.origin_transfer_id.clone() {
            let mut fast_transfer = FastTransfer::from_transfer(
                transfer_message.clone(),
                self.get_token_id(&transfer_message.token),
            );
            fast_transfer.transfer_id = origin_transfer_id;

            if let Some(fast_transfer_status) = self.get_fast_transfer_status(&fast_transfer.id()) {
                // For fast transfers we need to wait for finalization of the first leg (Origin chain -> Near) before allowing fee claim.
                // This confirms that fast transfer was executed with correct parameters.
                // Othewise malicious relayer can create a fast transfer with arbitrary high fee and claim it here.
                if fast_transfer_status.finalised {
                    self.remove_fast_transfer(&fast_transfer.id());
                } else {
                    env::panic_str(BridgeError::FastTransferNotFinalised.to_string().as_str());
                }
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        let token_address = self
            .get_token_address(transfer_message.get_destination_chain(), token.clone())
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-tests/src/environment.rs (L589-611)
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
```

**File:** near/omni-tests/src/relayer_staking.rs (L100-160)
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

        // Verify application exists
        let application: Option<serde_json::Value> = env
            .bridge_contract
            .view("get_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(application.is_some());

        // Before waiting period, relayer should not be trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(!is_trusted);

        // Fast forward past waiting period
        env.worker.fast_forward(100).await?;

        // After waiting period, relayer should be trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(is_trusted);

        // Verify stake is stored
        let stake: Option<U128> = env
            .bridge_contract
            .view("get_relayer_stake")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(stake.is_some());
        assert!(stake.unwrap().0 >= 1_000 * 10u128.pow(24));

        // Verify application is no longer pending
        let application: Option<serde_json::Value> = env
            .bridge_contract
            .view("get_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(application.is_none());

        Ok(())
```
