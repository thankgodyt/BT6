### Title
Trusted-Relayer Status Check on `claim_fee` Permanently Freezes Earned Fee Tokens When Relayer Resigns or Is Revoked — (`near/omni-bridge/src/lib.rs`)

### Summary

`claim_fee` is gated by the `#[trusted_relayer]` macro, which requires the caller to be a currently-active trusted relayer. Simultaneously, `claim_fee_callback` enforces that only the specific `fee_recipient` embedded in the on-chain proof can collect the fee. If a relayer resigns or is revoked after executing a fast transfer (or after signing a transfer with themselves as `fee_recipient`) but before the destination-chain proof is available to submit, neither the original relayer nor any other party can ever call `claim_fee` for that transfer. The fee tokens are permanently frozen in the bridge contract.

### Finding Description

`claim_fee` carries two independent restrictions that together create an irrecoverable dead-end:

**Restriction 1 — caller must be a currently-trusted relayer:** [1](#0-0) 

The `#[trusted_relayer]` attribute rejects any caller that is not presently in the active-relayer set, mirroring the `ValidatorStatus.ACTIVE` check in the original report.

**Restriction 2 — caller must equal the `fee_recipient` recorded in the proof:** [2](#0-1) 

The `fee_recipient` is cryptographically bound in the destination-chain event proof. No other account can satisfy this check.

When a relayer executes a fast transfer to a non-NEAR chain, `fast_fin_transfer_to_other_chain` burns/locks the principal and stores a second-leg `TransferMessage` in `pending_transfers` with the fee portion still accounted for inside the bridge: [3](#0-2) 

The fee is only released when `claim_fee_callback` calls `send_fee_internal`: [4](#0-3) 

If the relayer resigns (`resign_trusted_relayer`) or is revoked by the DAO (`reject_relayer_application`) before the destination-chain proof is available, the fee tokens remain locked in the bridge's accounting indefinitely. The pending `TransferMessage` also persists in `pending_transfers` as a storage leak.

The relayer staking system confirms that resignation immediately removes trusted status and returns the stake: [5](#0-4) 

### Impact Explanation

Fee tokens earned by a relayer for executing a fast transfer to a non-NEAR destination chain are permanently frozen in the bridge contract. The `pending_transfers` entry for the second leg is never removed. The only escape is DAO intervention via `transfer_token_as_dao`, which is an out-of-band privileged action and does not restore the fee to the rightful relayer. This constitutes **fee mis-accounting / permanent freezing of bridged funds** within the allowed impact scope.

### Likelihood Explanation

**Low.** The window requires a relayer to resign or be revoked after submitting a fast transfer but before the destination-chain proof is finalized and submitted. Fast transfers are time-sensitive, so the window is narrow but realistic — especially for chains with longer finality (e.g., Ethereum mainnet) or if the DAO revokes a relayer for misconduct while that relayer has pending fee claims.

### Recommendation

Remove the `#[trusted_relayer]` gate from `claim_fee`. The `fee_recipient == predecessor_account_id` check in `claim_fee_callback` already ensures only the correct party can collect the fee; the additional trusted-relayer check adds no security benefit and creates the described dead-end. Alternatively, allow the `fee_recipient` to call `claim_fee` regardless of current relayer status, since the fee was earned at the time the fast transfer was executed.

### Proof of Concept

1. Relayer A applies and becomes a trusted relayer (stake deposited, waiting period elapsed).
2. Relayer A calls `ft_transfer_call` on the token contract with a `FastFinTransferMsg` targeting a Base-chain recipient. `fast_fin_transfer_to_other_chain` burns the principal, stores a second-leg `TransferMessage` in `pending_transfers` with `origin_transfer_id = Some(fast_transfer_id)`, and records `FastTransferStatus { relayer: RelayerA, finalised: false }`.
3. A regular relayer calls `sign_transfer` on the second-leg transfer. Because `fee > 0`, the `TransferMessage` remains in `pending_transfers` after signing.
4. Relayer A calls `resign_trusted_relayer`. Stake is returned; Relayer A is removed from the trusted set.
5. The signed payload is submitted to Base. Base emits `FinTransfer` with `fee_recipient = RelayerA`.
6. Relayer A attempts `claim_fee` with the Base proof → **panics at `#[trusted_relayer]`** because Relayer A is no longer active.
7. Any other trusted relayer attempts `claim_fee` with the same proof → **panics at `OnlyFeeRecipientCanClaim`** because `fee_recipient (RelayerA) != predecessor_account_id`.
8. The fee tokens and the `pending_transfers` entry are permanently stuck. No permissionless path exists to recover them. [6](#0-5) [2](#0-1) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L914-972)
```rust
    fn fast_fin_transfer_to_other_chain(
        &mut self,
        fast_transfer: &FastTransfer,
        storage_payer: AccountId,
        relayer_id: AccountId,
    ) {
        if fast_transfer.recipient.is_utxo_chain() {
            let btc_account_id = self.get_utxo_chain_token(fast_transfer.get_destination_chain());
            require!(
                fast_transfer.token_id == btc_account_id,
                BridgeError::NativeTokenRequiredForChain.as_ref()
            );
        }

        let amount_without_fee = fast_transfer
            .amount_without_fee()
            .near_expect(BridgeError::InvalidFee);

        self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());

        self.lock_tokens_if_needed(
            fast_transfer.get_destination_chain(),
            &fast_transfer.token_id,
            amount_without_fee,
        );

        let mut required_balance =
            self.add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone());

        let destination_nonce =
            self.get_next_destination_nonce(fast_transfer.get_destination_chain());
        self.current_origin_nonce += 1;

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(fast_transfer.token_id.clone()),
            amount: fast_transfer.amount,
            recipient: fast_transfer.recipient.clone(),
            fee: fast_transfer.fee.clone(),
            sender: OmniAddress::Near(env::current_account_id()),
            msg: fast_transfer.msg.clone(),
            destination_nonce,
            origin_transfer_id: Some(fast_transfer.transfer_id.clone()),
        };
        let new_transfer_id = transfer_message.get_transfer_id();

        required_balance = self
            .add_transfer_message(transfer_message, storage_payer.clone())
            .saturating_add(required_balance);

        env::log_str(
            &OmniBridgeEvent::FastTransferEvent {
                fast_transfer: fast_transfer.clone(),
                new_transfer_id: Some(new_transfer_id),
            }
            .to_log_string(),
        );

        self.update_storage_balance(storage_payer, required_balance, NearToken::from_near(0));
```

**File:** near/omni-bridge/src/lib.rs (L1054-1064)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1083-1086)
```rust
        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2650-2701)
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
```

**File:** near/omni-tests/src/relayer_staking.rs (L336-368)
```rust
        let balance_before_resign = applicant.view_account().await?.balance;

        // Resign
        applicant
            .call(env.bridge_contract.id(), "resign_trusted_relayer")
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Verify relayer is no longer trusted
        let is_trusted: bool = env
            .bridge_contract
            .view("is_trusted_relayer")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(!is_trusted);

        // Verify NEAR was returned
        let balance_after_resign = applicant.view_account().await?.balance;
        assert!(balance_after_resign.as_yoctonear() > balance_before_resign.as_yoctonear());

        // Verify stake is removed
        let stake: Option<U128> = env
            .bridge_contract
            .view("get_relayer_stake")
            .args_json(json!({"account_id": applicant.id()}))
            .await?
            .json()?;
        assert!(stake.is_none());

        Ok(())
```
