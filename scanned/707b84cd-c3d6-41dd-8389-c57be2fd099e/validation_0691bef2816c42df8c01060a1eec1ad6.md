### Title
Trusted-Relayer Check on `claim_fee()` Permanently Locks Earned Fee Tokens After Relayer Removal - (`near/omni-bridge/src/lib.rs`)

### Summary
`claim_fee()` is gated by the `#[trusted_relayer]` macro. If a relayer is removed from the trusted-relayer set (via `resign_trusted_relayer` or `reject_relayer_application`) after they have already called `sign_transfer()` but before they call `claim_fee()`, the fee tokens they earned are permanently locked in the bridge contract. No other party can claim those tokens because `claim_fee_callback()` additionally enforces `fee_recipient == predecessor_account_id`.

### Finding Description

`claim_fee()` carries two independent guards that together create the lock:

1. The method-level `#[trusted_relayer]` attribute (and the impl-block-level `#[trusted_relayer]` macro) reject any caller who is not currently a trusted relayer. [1](#0-0) 

2. Inside `claim_fee_callback()`, the contract enforces that only the exact `fee_recipient` embedded in the signed MPC payload may collect the fee. [2](#0-1) 

The `fee_recipient` is fixed at `sign_transfer()` time and is cryptographically bound into the MPC-signed payload. [3](#0-2) 

The trusted-relayer set is mutable at runtime: a relayer can resign voluntarily, or the DAO can forcibly revoke them via `reject_relayer_application`. [4](#0-3) [5](#0-4) 

The impl block that contains `claim_fee` is annotated with the `#[trusted_relayer]` macro, confirming the check is applied to every method in the block including `claim_fee`. [6](#0-5) 

### Impact Explanation

When a relayer is removed after signing but before claiming:

- The fee portion of the user's original token transfer (held by the bridge contract) cannot be retrieved by the relayer (blocked by `#[trusted_relayer]`).
- No substitute caller can claim it either (blocked by `fee_recipient == predecessor_account_id`).
- The fee tokens remain in `pending_transfers` indefinitely with no on-chain recovery path that does not require DAO intervention (granting `UnrestrictedRelayer` role to the removed relayer).

The locked tokens are bridged user funds (NEP-141 tokens originally sent via `ft_transfer_call`), constituting permanent freezing of bridged funds. [7](#0-6) 

### Likelihood Explanation

The scenario is realistic:

- Relayers sign many transfers in bulk before claiming fees.
- The DAO can revoke a relayer at any time (e.g., for misconduct or operational reasons).
- A relayer can also resign voluntarily without first draining all pending fee claims.
- The window between `sign_transfer()` and `claim_fee()` can span multiple blocks or even days (the destination-chain finalization proof must be obtained first).

### Recommendation

Remove the `#[trusted_relayer]` guard from `claim_fee()`. The function is already protected by:
- Cryptographic proof verification (`verify_proof`).
- The `fee_recipient == predecessor_account_id` check in `claim_fee_callback()`, which ensures only the legitimate fee earner can collect.

The trusted-relayer check adds no security value here and only risks locking legitimately earned fees.

### Proof of Concept

1. Relayer R becomes trusted (stake deposited, waiting period elapsed).
2. R calls `sign_transfer(transfer_id, fee_recipient = R, fee)` — MPC signs a payload embedding R as fee recipient.
3. The signed transaction is broadcast; the destination chain finalizes the transfer.
4. DAO calls `reject_relayer_application(R)` — R is removed from the trusted set and R's stake is transferred to the DAO.
5. R calls `claim_fee(proof_args)` — the `#[trusted_relayer]` check fires and the call is rejected.
6. No other account can call `claim_fee` and pass the `fee_recipient == predecessor_account_id` check in `claim_fee_callback`, because the MPC-signed payload irrevocably names R as the fee recipient.
7. The fee tokens remain locked in the bridge contract with no permissionless recovery path. [1](#0-0) [8](#0-7)

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

**File:** near/omni-bridge/src/lib.rs (L1066-1086)
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

**File:** near/omni-tests/src/relayer_staking.rs (L338-368)
```rust
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

**File:** near/omni-tests/src/relayer_staking.rs (L467-491)
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

        Ok(())
    }
```
