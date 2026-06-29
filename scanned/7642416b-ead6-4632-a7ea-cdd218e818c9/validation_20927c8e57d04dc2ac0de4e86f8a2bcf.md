### Title
Fees Permanently Stuck When Fee-Recipient Relayer Loses Trusted Status - (`near/omni-bridge/src/lib.rs`)

### Summary

`claim_fee()` is the sole mechanism for distributing relayer fees on NEAR → EVM transfers. It enforces two independent guards: `#[trusted_relayer]` (caller must be a trusted relayer or bypass-role holder) and an inner `fee_recipient == predecessor_account_id` check. When the designated `fee_recipient` loses trusted-relayer status — by resigning or being revoked by the DAO — neither guard can be satisfied simultaneously by any account, making the fee permanently unclaimable.

### Finding Description

The NEAR → EVM transfer flow works as follows:

1. User calls `ft_transfer_call` → `init_transfer` → tokens are burned/locked on NEAR (full amount including fee).
2. A trusted relayer calls `sign_transfer(transfer_id, fee_recipient, fee)`, embedding the `fee_recipient` into the MPC-signed `TransferMessagePayload`.
3. The relayer submits the signed payload on EVM; tokens (minus fee) are delivered to the recipient.
4. The relayer calls `claim_fee()` on NEAR with a proof of EVM finalization to collect the fee.

`claim_fee()` carries two mandatory guards:

```rust
// near/omni-bridge/src/lib.rs:1054-1064
#[payable]
#[trusted_relayer]                          // Guard 1: caller must be trusted relayer
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise { ... }
```

```rust
// near/omni-bridge/src/lib.rs:1083-1086
require!(
    fee_recipient == *predecessor_account_id,  // Guard 2: caller must BE the fee_recipient
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
```

The `#[trusted_relayer]` macro is configured with bypass roles:

```rust
// near/omni-bridge/src/lib.rs:245-249
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

If the `fee_recipient` loses trusted status (via `resign_trusted_relayer` or DAO calling `reject_relayer_application`):

- The `fee_recipient` is blocked by Guard 1 (no longer trusted).
- The DAO can bypass Guard 1 but fails Guard 2 (`fee_recipient != DAO account`).
- No other account can satisfy both guards simultaneously.

There is no `cancel_transfer`, no alternative fee-distribution path, and no DAO rescue function that removes the `pending_transfers` entry and refunds the fee. The `pending_transfers` entry persists indefinitely.

### Impact Explanation

For **deployed tokens** (burned on NEAR at `init_transfer`): the fee portion was burned but is never minted to anyone — it is permanently destroyed.

For **locked tokens**: the fee portion remains locked in the bridge's `locked_tokens` accounting forever, with no mechanism to release it.

In both cases the `pending_transfers` entry is never removed, and the fee tokens are permanently frozen. The user's principal is already delivered on EVM; only the relayer fee is lost.

### Likelihood Explanation

Low. The window between `sign_transfer` (which embeds `fee_recipient`) and `claim_fee` (which distributes the fee) is typically short. However, the scenario is reachable without any key compromise:

- A relayer voluntarily calls `resign_trusted_relayer` before claiming pending fees.
- The DAO calls `reject_relayer_application` to revoke an active relayer that has unclaimed fees.

Both paths are normal protocol operations with no adversarial precondition beyond the ordering of events.

### Recommendation

Decouple fee-recipient identity from trusted-relayer status at claim time. Options:

1. **Remove `#[trusted_relayer]` from `claim_fee()`** and rely solely on the `fee_recipient == predecessor_account_id` check plus proof verification. The proof already cryptographically binds the fee_recipient; the trusted-relayer guard is redundant and harmful here.
2. **Add a DAO-callable rescue function** that, given a `TransferId`, distributes the fee to the recorded `fee_recipient` (or a DAO-specified address) without requiring the caller to be the fee_recipient.
3. **Claim fee atomically in `sign_transfer_callback`** when `fee.is_zero()` is false, so the fee is distributed before the relayer's status can change.

### Proof of Concept

```
1. Trusted relayer R calls sign_transfer(transfer_id, fee_recipient=R, fee=X).
   → MPC signs payload with fee_recipient=R embedded.
   → pending_transfers[transfer_id] holds amount including X.

2. EVM finalizes: recipient receives (amount - X) tokens.

3. DAO calls reject_relayer_application(R).
   → R is no longer a trusted relayer.
   → R's stake is transferred to DAO.

4. R calls claim_fee(proof_of_evm_finalization).
   → #[trusted_relayer] macro rejects R: "not a trusted relayer".
   → Fee X is permanently stuck.

5. DAO calls claim_fee(proof_of_evm_finalization).
   → #[trusted_relayer] passes (DAO has bypass_role).
   → claim_fee_callback: require!(fee_recipient == predecessor_account_id)
      → fee_recipient = R, predecessor = DAO → PANIC.
   → Fee X is permanently stuck.

6. No other code path exists to remove pending_transfers[transfer_id]
   or distribute the fee. Tokens are frozen forever.
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

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

**File:** near/omni-bridge/src/lib.rs (L1079-1092)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
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
