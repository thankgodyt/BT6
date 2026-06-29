### Title
Silent Permanent Loss of Native Fees via Detached Promise in `send_fee_internal` — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`claim_fee_callback` irrevocably removes the pending transfer message from storage **before** dispatching fee payments. The native-fee leg is dispatched with `.detach()` (fire-and-forget), so any failure of that cross-contract call is silently swallowed. Because the transfer record is already gone, the relayer has no way to retry, and the native fee is permanently lost.

---

### Finding Description

`claim_fee_callback` (lines 1066–1134) executes the following sequence:

1. **Removes** the transfer message from storage unconditionally at line 1094.
2. Calls `send_fee_internal` at line 1133.

Inside `send_fee_internal` (lines 2650–2702):

```rust
// native fee — fire-and-forget, result is never checked
ext_token::ext(self.get_native_token_id(origin_chain))
    .with_static_gas(MINT_TOKEN_GAS)
    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
    .detach();          // ← failure is silently discarded

// token fee — returned as the main promise
ext_token::ext(token)
    .with_static_gas(FT_TRANSFER_GAS)
    .with_attached_deposit(ONE_YOCTO)
    .ft_transfer(fee_recipient, U128(token_fee), None)
    .into()
``` [1](#0-0) [2](#0-1) [3](#0-2) 

In NEAR's execution model, state mutations committed before a `Promise` is returned are **not rolled back** if the promise later fails. Because the transfer message is removed synchronously inside `claim_fee_callback` (before any promise is scheduled), a failure of either the detached native-fee mint or the returned token-fee transfer leaves the bridge in a state where:

- The transfer record no longer exists (cannot retry).
- The native fee was either never minted or minted but the result ignored.
- The relayer permanently loses the native fee they earned.

The `claim_fee` entry point does **not** require the caller to supply storage-deposit actions for the native token, unlike `fin_transfer` which enforces this via `StorageNativeFeeRecipientOmitted`. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

A relayer who completes a cross-chain transfer carrying `native_fee > 0` (EVM → NEAR with a wrapped-native-token fee) calls `claim_fee`. If the native-token `mint` call fails (e.g., the relayer has not registered storage on the native-token contract, or `MINT_TOKEN_GAS` is insufficient for the token's `ft_on_transfer` hook), the native fee is permanently destroyed: the transfer message is gone, the detached promise result is never inspected, and no recovery path exists. This constitutes **permanent loss of bridged funds** belonging to the relayer.

---

### Likelihood Explanation

- `native_fee > 0` is a supported and documented fee path for EVM-origin transfers.
- The `claim_fee` flow provides **no** mechanism for the relayer to pre-register storage on the native-token contract, unlike `fin_transfer`.
- A relayer who has not previously interacted with the wrapped-native-token contract will have no storage registered; the `mint` will panic inside the token contract, the detached promise silently fails, and the fee is lost.
- No privileged access or external collusion is required — any trusted relayer processing such a transfer is exposed.

---

### Recommendation

1. **Remove the transfer message only after fee delivery succeeds.** Restructure `claim_fee_callback` to first dispatch fees and handle the result in a subsequent callback that removes the transfer message on success (mirroring the `fin_transfer_send_tokens_callback` pattern).
2. **Do not use `.detach()` for value-bearing promises.** Chain the native-fee mint into the main promise sequence so that a failure is observable and the state can be rolled back or retried.
3. **Require storage-deposit actions for the native-token recipient** in `claim_fee`, consistent with the requirement already enforced in `process_fin_transfer_to_near`.

---

### Proof of Concept

1. A relayer executes a fast transfer for an EVM → NEAR message where `native_fee = 1e18` (1 wETH equivalent).
2. The relayer calls `claim_fee` with a valid `FinTransfer` proof. The relayer has **not** registered storage on the wrapped-native-token contract.
3. `claim_fee_callback` fires:
   - Line 1094: `remove_transfer_message` — transfer record deleted, state committed.
   - Line 1133: `send_fee_internal` called.
4. Inside `send_fee_internal`, the native-token `mint` is dispatched with `.detach()`. The token contract panics (no storage for `fee_recipient`). The panic is silently discarded.
5. The token-fee `ft_transfer` (or `mint`) is returned as the main promise and succeeds.
6. Result: the relayer receives the token fee but **permanently loses** the native fee. The transfer message is gone; no retry is possible. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1057-1063)
```rust
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
```

**File:** near/omni-bridge/src/lib.rs (L1066-1134)
```rust
    #[private]
    #[payable]
    pub fn claim_fee_callback(
        &mut self,
        #[serializer(borsh)] predecessor_account_id: &AccountId,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> PromiseOrValue<()> {
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L1935-1948)
```rust
        if transfer_message.fee.native_fee.0 > 0 {
            let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

            require!(
                Self::check_storage_balance_result(
                    (storage_deposit_action_index + 1)
                        .try_into()
                        .near_expect(BridgeError::Cast)
                ) && storage_deposit_actions[storage_deposit_action_index].account_id
                    == fee_recipient
                    && storage_deposit_actions[storage_deposit_action_index].token_id
                        == native_token_id,
                BridgeError::StorageNativeFeeRecipientOmitted.as_ref()
            );
```

**File:** near/omni-bridge/src/lib.rs (L2650-2702)
```rust
    fn send_fee_internal(
        &mut self,
        transfer_message: &TransferMessage,
        fee_recipient: AccountId,
        token_fee: u128,
    ) -> PromiseOrValue<()> {
        if transfer_message.fee.native_fee.0 != 0 {
            let origin_chain = transfer_message.origin_transfer_id.as_ref().map_or_else(
                || transfer_message.get_origin_chain(),
                |origin_transfer_id| origin_transfer_id.origin_chain,
            );

            if origin_chain.is_utxo_chain() {
                env::panic_str(BridgeError::NativeFeeForUtxoChain.to_string().as_str())
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        env::log_str(
            &OmniBridgeEvent::ClaimFeeEvent {
                transfer_message: transfer_message.clone(),
            }
            .to_log_string(),
        );

        self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);

        if token_fee > 0 {
            if self.is_deployed_token(&token) {
                ext_token::ext(token)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient, U128(token_fee), None)
                    .into()
            } else {
                ext_token::ext(token)
                    .with_static_gas(FT_TRANSFER_GAS)
                    .with_attached_deposit(ONE_YOCTO)
                    .ft_transfer(fee_recipient, U128(token_fee), None)
                    .into()
            }
        } else {
            PromiseOrValue::Value(())
        }
    }
```
