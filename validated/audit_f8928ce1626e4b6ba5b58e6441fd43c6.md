### Title
Pending NEAR→EVM Transfers Permanently Locked After `migrate_deployed_token` Removes Token Address Mapping — (`File: near/omni-bridge/src/lib.rs`)

### Summary
`migrate_deployed_token` removes the `token_id_to_address` entry for `old_token` without checking for in-flight pending transfers. Any NEAR→EVM transfer that was initiated before the migration but not yet signed becomes permanently uncompletable: `sign_transfer` panics with `FailedToGetTokenAddress`, and there is no public cancel/refund path. The user's tokens (burned or held by the bridge during `ft_on_transfer`) are permanently lost.

### Finding Description

`migrate_deployed_token` performs the following state mutations: [1](#0-0) 

It removes `(origin_chain, old_token)` from `token_id_to_address` and inserts `(origin_chain, new_token)`. No check is made for pending transfers that reference `old_token`.

When a user initiates a NEAR→EVM transfer of `old_token` via `ft_transfer_call`, the bridge stores a `TransferMessage` in `pending_transfers` with `token = OmniAddress::Near(old_token)`: [2](#0-1) 

A relayer must later call `sign_transfer` to obtain the MPC signature needed to mint tokens on EVM. `sign_transfer` resolves the destination-chain token address via: [3](#0-2) 

`get_token_id(OmniAddress::Near(old_token))` returns `old_token`. Then `get_token_address(destination_chain, old_token)` performs `token_id_to_address.get(&(destination_chain, old_token))`. After `migrate_deployed_token`, this entry no longer exists, so the call panics: [4](#0-3) 

There is no public function to cancel a pending transfer and refund the user. `remove_transfer_message` is internal-only: [5](#0-4) 

### Impact Explanation

The user's tokens are irrecoverably lost:
- For deployed (bridge) tokens, the tokens are transferred into the bridge during `ft_on_transfer` and burned as part of the outbound flow. After migration, the EVM minting step can never be authorized.
- Even if tokens are merely held by the bridge, there is no cancel/refund path, so they remain permanently locked.

This is a permanent freezing of bridged funds — a Critical impact per the allowed scope.

### Likelihood Explanation

Low. It requires a pending (unsigned) NEAR→EVM transfer to exist at the exact moment the DAO calls `migrate_deployed_token`. Token migrations are infrequent operational events, but the protocol provides no guard (no check, no drain period, no cancel mechanism) to prevent this race condition.

### Recommendation

Before removing the old token's address mapping, `migrate_deployed_token` should verify that no pending transfers reference `old_token` (e.g., by maintaining a per-token pending-transfer counter). Alternatively, provide a public `cancel_transfer` function that allows the original sender to reclaim tokens from a pending transfer, so users can self-rescue before or after a migration.

### Proof of Concept

1. User calls `old_token.ft_transfer_call(bridge, 1000, '{"InitTransfer": {..., "recipient": "0xEVM..."}}')`.
2. Bridge stores `TransferMessage { token: Near(old_token), ... }` in `pending_transfers` with `origin_nonce = N`.
3. DAO calls `migrate_deployed_token(Eth, old_token, new_token)`.
   - `token_id_to_address.remove(&(Eth, old_token))` executes.
4. Relayer calls `sign_transfer({ origin_chain: Near, origin_nonce: N }, ...)`.
5. Inside `sign_transfer`: `get_token_address(Eth, old_token)` returns `None` → `env::panic_str("ERR_FAILED_TO_GET_TOKEN_ADDRESS")`.
6. The pending transfer can never be signed. The user's 1000 `old_token` (burned or held by the bridge) are permanently lost. No public cancel path exists. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L447-521)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L540-553)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L1604-1664)
```rust
    #[access_control_any(roles(Role::DAO))]
    #[payable]
    pub fn migrate_deployed_token(
        &mut self,
        origin_chain: ChainKind,
        old_token: AccountId,
        new_token: AccountId,
    ) {
        require!(
            env::attached_deposit() >= NEP141_DEPOSIT,
            BridgeError::NotEnoughAttachedDeposit.as_ref()
        );

        require!(
            self.deployed_tokens.remove(&old_token),
            BridgeError::OldTokenNotDeployed.as_ref(),
        );
        require!(
            self.deployed_tokens.insert(&new_token),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2.remove(&old_token);
        self.deployed_tokens_v2.insert(&new_token, &origin_chain);

        let origin_address = self
            .token_id_to_address
            .remove(&(origin_chain, old_token.clone()))
            .near_expect(BridgeError::FailedToGetTokenAddress);

        require!(
            self.token_id_to_address
                .insert(&(origin_chain, new_token.clone()), &origin_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );

        self.token_address_to_id
            .insert(&origin_address, &new_token)
            .near_expect(BridgeError::ExpectedToOverwriteTokenAddress);

        require!(
            self.migrated_tokens
                .insert(&old_token, &new_token)
                .is_none(),
            BridgeError::TokenAlreadyMigrated.as_ref()
        );

        ext_token::ext(new_token.clone())
            .with_static_gas(STORAGE_DEPOSIT_GAS)
            .with_attached_deposit(NEP141_DEPOSIT)
            .storage_deposit(&env::current_account_id(), Some(true))
            .detach();

        env::log_str(
            &OmniBridgeEvent::MigrateTokenEvent {
                old_token_id: old_token,
                new_token_id: new_token,
            }
            .to_log_string(),
        );
    }
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
