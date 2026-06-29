### Title
Fee Recipient Cannot Claim Fees When Not a Trusted Relayer — Permanent Freezing of Bridge Fees (`near/omni-bridge/src/lib.rs`)

### Summary

`claim_fee` is gated by `#[trusted_relayer]`, but the `fee_recipient` embedded in the proof can be any `AccountId`. If the `fee_recipient` is not a trusted relayer — either because it was set to a separate treasury account, or because the relayer's trusted status was revoked after `sign_transfer` — neither the fee_recipient nor any other party can ever claim the fee. The tokens are permanently frozen inside the bridge.

### Finding Description

The `sign_transfer` function accepts an arbitrary `fee_recipient: Option<AccountId>` parameter and embeds it in the MPC-signed payload: [1](#0-0) 

The `claim_fee` function is restricted to trusted relayers only: [2](#0-1) 

Inside `claim_fee_callback`, the contract additionally enforces that the caller **is** the `fee_recipient` from the proof: [3](#0-2) 

These two constraints together require the caller to be **simultaneously** a trusted relayer **and** the `fee_recipient`. If the `fee_recipient` is not a trusted relayer, the fee can never be claimed:

- The `fee_recipient` account cannot call `claim_fee` (blocked by `#[trusted_relayer]`).
- Any other trusted relayer who calls `claim_fee` fails the `fee_recipient == predecessor_account_id` check.

The fee remains locked in `pending_transfers` indefinitely, and `send_fee_internal` — which also calls `unlock_tokens_if_needed` — is never reached: [4](#0-3) 

### Impact Explanation

The fee portion of the bridged amount is permanently frozen inside the NEAR bridge contract. Because `remove_transfer_message` is only called from `claim_fee_callback`, the `pending_transfers` entry and the associated `locked_tokens` accounting are never cleaned up. The fee tokens — which are real bridged assets — cannot be recovered by any unprivileged party.

### Likelihood Explanation

Two realistic paths trigger this:

1. **Treasury fee collection**: A trusted relayer sets `fee_recipient` to a separate treasury/multisig account that is not registered as a trusted relayer. This is a common operational pattern.
2. **Relayer revocation**: A trusted relayer sets `fee_recipient` to themselves, but the DAO later calls `reject_relayer_application` (which revokes active relayers as shown in tests): [5](#0-4) 

After revocation, the former relayer can no longer call `claim_fee`, and no other trusted relayer can satisfy the `fee_recipient == predecessor_account_id` check.

### Recommendation

Remove the `#[trusted_relayer]` guard from `claim_fee`. The `claim_fee_callback` already enforces `fee_recipient == predecessor_account_id`, which is the correct and sufficient access control — only the designated fee recipient should be able to claim. The trusted-relayer check is redundant for security and actively harmful for liveness.

```rust
// Before
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { ... }

// After
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { ... }
```

### Proof of Concept

1. DAO configures a trusted relayer (`applicant`) with a 1000 NEAR stake.
2. A user calls `ft_transfer_call` → `init_transfer` on NEAR, locking 1000 tokens destined for Ethereum.
3. `applicant` calls `sign_transfer` with `fee_recipient = Some("treasury.near")` where `treasury.near` is **not** a trusted relayer.
4. MPC signs the payload; the relayer submits the signed transaction to Ethereum; Ethereum emits a `FinTransfer` event with `fee_recipient = "treasury.near"`.
5. `treasury.near` calls `claim_fee` with the Ethereum proof → **panics** at the `#[trusted_relayer]` guard.
6. `applicant` calls `claim_fee` with the same proof → **panics** at `require!(fee_recipient == *predecessor_account_id)` because `"treasury.near" != "applicant"`.
7. No account can ever call `claim_fee` successfully for this transfer. The fee tokens remain locked in `pending_transfers` forever, and `locked_tokens` is never decremented via `unlock_tokens_if_needed`. [6](#0-5)

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

**File:** near/omni-bridge/src/lib.rs (L1054-1086)
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

**File:** near/omni-tests/src/relayer_staking.rs (L467-488)
```rust
        // DAO revokes active relayer
        let dao_balance_before = dao_account.view_account().await?.balance;
        dao_account
            .call(env.bridge_contract.id(), "reject_relayer_application")
            .args_json(json!({"account_id": applicant.id()}))
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

        // Verify stake was transferred to DAO account
        let dao_balance_after = dao_account.view_account().await?.balance;
        assert!(dao_balance_after.as_yoctonear() > dao_balance_before.as_yoctonear());
```
