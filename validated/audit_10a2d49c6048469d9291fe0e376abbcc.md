### Title
Sub-Unit Transfer Permanently Locks Tokens With No Recovery Path — (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts and locks tokens for any amount that satisfies `fee < amount`, but the critical normalization check (`amount_to_transfer > 0`) only occurs later in `sign_transfer`. When a user bridges a token amount smaller than the decimal-precision gap between NEAR and the destination chain, the normalized amount is 0, `sign_transfer` permanently reverts, and the locked tokens have no recovery path.

### Finding Description

`init_transfer` validates only that `fee < amount`: [1](#0-0) 

It then locks/burns the tokens and stores the pending transfer: [2](#0-1) 

The normalization check is deferred to `sign_transfer`, which is called later by a trusted relayer: [3](#0-2) 

`normalize_amount` uses floor division: [4](#0-3) 

For a token with `origin_decimals=24` (NEAR) and `decimals=18` (EVM), any `amount_without_fee < 1_000_000` normalizes to 0. `sign_transfer` then permanently reverts with `ERR_INVALID_AMOUNT_TO_TRANSFER`.

`sign_transfer` is restricted to trusted relayers only — the sender cannot call it: [5](#0-4) 

This is confirmed by the integration test `test_untrusted_sender_cannot_sign_transfer`: [6](#0-5) 

There is no user-callable cancel or refund function for pending transfers. The only removal paths are `remove_transfer_message` (called from `claim_fee` after destination-chain finalization) and `remove_transfer_message_without_refund` (called on internal storage failures): [7](#0-6) 

Neither is reachable by the user for a transfer that can never be signed.

### Impact Explanation

Any user who initiates a NEAR→EVM (or NEAR→Solana, etc.) transfer with `amount_without_fee < 10^(origin_decimals − decimals)` will have their tokens permanently locked in the bridge with no recovery. This is permanent freezing of bridged funds, which falls squarely within the critical impact scope.

The SECURITY.md comment acknowledges that "dust stays locked/burned" when `fee=0`, but this refers to sub-unit remainders after normalization of a valid amount. The scenario here is distinct: the *entire* `amount_without_fee` normalizes to 0, making the transfer permanently unsignable.

### Likelihood Explanation

The entry path is the standard user-facing `ft_transfer_call` → `ft_on_transfer` → `init_transfer` flow. No special role or privilege is required. A user who accidentally sends a small test amount (e.g., 1 yocto-unit of a 24-decimal NEAR token to an 18-decimal EVM chain) will trigger this silently — `init_transfer` succeeds and emits an `InitTransferEvent`, giving no indication the transfer is unrecoverable.

### Recommendation

Add a normalization pre-check inside `init_transfer` (or `init_transfer_internal`) before locking tokens:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the existing check in `sign_transfer` but gates it before any state mutation or token lock occurs, ensuring the user receives a refund via the NEP-141 `ft_transfer_call` return value.

### Proof of Concept

1. Register a token with `origin_decimals=24`, `decimals=18` (6-decimal precision gap → divisor = 1,000,000).
2. Call `ft_transfer_call` with `amount=500_000`, `fee=0`, valid EVM recipient.
3. `init_transfer` passes (`fee=0 < amount=500_000`). Tokens are locked. `InitTransferEvent` is emitted.
4. Any trusted relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000 - 0, {origin:24, dest:18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0)` → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. No trusted relayer can ever sign this transfer. No cancel function exists. The 500,000 units are permanently locked.

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-446)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
```

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L2194-2223)
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

    fn remove_transfer_message_without_refund(
        &mut self,
        transfer_id: TransferId,
    ) -> TransferMessage {
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        transfer.message
```

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-tests/src/init_transfer.rs (L749-819)
```rust
    async fn test_untrusted_sender_cannot_sign_transfer(
        build_artifacts: &BuildArtifacts,
    ) -> anyhow::Result<()> {
        let sender_balance_token = 1_000_000;
        let transfer_amount = 100;
        let init_transfer_msg = InitTransferMsg {
            native_token_fee: U128(0),
            fee: U128(0),
            recipient: eth_eoa_address(),
            msg: None,
            external_id: None,
        };

        let env = TestEnv::new(sender_balance_token, false, build_artifacts).await?;

        let storage_deposit_amount = get_balance_required_for_account(
            &env.locker_contract,
            &env.sender_account,
            &init_transfer_msg,
            None,
        )
        .await?;

        env.sender_account
            .call(env.locker_contract.id(), "storage_deposit")
            .args_json(json!({
                "account_id": env.sender_account.id(),
            }))
            .deposit(storage_deposit_amount)
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        let transfer_result = env
            .sender_account
            .call(env.token_contract.id(), "ft_transfer_call")
            .args_json(json!({
                "receiver_id": env.locker_contract.id(),
                "amount": U128(transfer_amount),
                "memo": None::<String>,
                "msg": serde_json::to_string(&BridgeOnTransferMsg::InitTransfer(init_transfer_msg))?,
            }))
            .deposit(NearToken::from_yoctonear(1))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        let transfer_message = get_transfer_message_from_event(&transfer_result)?;

        // sender_account is not a trusted relayer, so sign_transfer should fail
        let result = env
            .sender_account
            .call(env.locker_contract.id(), "sign_transfer")
            .args_json(json!({
                "transfer_id": TransferId {
                    origin_chain: ChainKind::Near,
                    origin_nonce: transfer_message.origin_nonce,
                },
                "fee_recipient": env.relayer_account.id(),
                "fee": &Some(transfer_message.fee.clone()),
            }))
            .max_gas()
            .transact()
            .await?;

        assert!(
            result.into_result().is_err(),
            "Unprivileged sender should not be able to call sign_transfer"
        );
```
