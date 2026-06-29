Audit Report

## Title
Deferred Normalization Check Permanently Locks Tokens With No Recovery Path — (`near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` validates only that `fee < amount` before locking/burning tokens and storing the pending transfer. The critical check that `normalize_amount(amount_without_fee) > 0` is deferred to `sign_transfer`, which is restricted to trusted relayers. When a user bridges a token amount smaller than the decimal-precision gap (e.g., any amount < 1,000,000 for a 24→18 decimal token), the normalized amount is 0, `sign_transfer` permanently reverts, and no user-callable recovery path exists. The locked tokens are permanently frozen.

## Finding Description

`init_transfer` (via `ft_on_transfer`) validates only that `fee < amount`: [1](#0-0) 

It then calls `init_transfer_internal`, which locks/burns the full token amount and stores the pending transfer: [2](#0-1) 

The normalization check is deferred to `sign_transfer`, which is gated by `#[trusted_relayer]`: [3](#0-2) 

`normalize_amount` uses floor division: [4](#0-3) 

For a token with `origin_decimals=24` and `decimals=18`, any `amount_without_fee < 1_000_000` produces `normalize_amount(...) = 0`, causing `sign_transfer` to permanently revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`.

Both `remove_transfer_message` and `remove_transfer_message_without_refund` are private functions with no public wrapper: [5](#0-4) 

There are no public `cancel`, `refund`, `withdraw`, or `revert` functions in the contract. The only removal path (`remove_transfer_message`) is called from `claim_fee` after destination-chain finalization — which can never occur for a transfer that can never be signed.

## Impact Explanation

This is permanent freezing of bridged funds triggered by an unprivileged user through the standard `ft_transfer_call` flow. The entire `amount_without_fee` is locked/burned with no recovery path, matching the critical impact class: *permanent freezing of bridged funds*. The SECURITY.md comment about "dust stays locked/burned" refers only to sub-unit remainders after normalization of a valid (non-zero normalized) amount — it does not cover the case where the entire transferred amount normalizes to 0.

## Likelihood Explanation

The exploit path requires no special role or privilege. Any user calling `ft_transfer_call` with a small amount (e.g., 1 yocto-unit of a 24-decimal NEAR token bridged to an 18-decimal EVM chain) triggers this silently. `init_transfer` succeeds and emits an `InitTransferEvent`, giving no indication the transfer is unrecoverable. This is a realistic user mistake (sending a test/dust amount) and is repeatable for any token pair with `origin_decimals > decimals`.

## Recommendation

Add a normalization pre-check inside `init_transfer_internal` (or `init_transfer`) before any state mutation or token lock occurs. Retrieve the token's `Decimals` from `token_decimals`, call `Self::normalize_amount(amount_without_fee, decimals)`, and `require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref())`. This mirrors the existing check in `sign_transfer` but gates it before locking, ensuring the NEP-141 `ft_transfer_call` return value refunds the user automatically.

## Proof of Concept

1. Register a token with `origin_decimals=24`, `decimals=18` (divisor = 1,000,000).
2. Call `ft_transfer_call` with `amount=500_000`, `fee=0`, valid EVM recipient.
3. `init_transfer` passes (`0 < 500_000`). Tokens are locked. `InitTransferEvent` is emitted.
4. Any trusted relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000, {origin:24, dest:18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. No trusted relayer can ever sign this transfer. No cancel function exists. The 500,000 units are permanently locked.

This can be demonstrated as an integration test analogous to `test_untrusted_sender_cannot_sign_transfer` in `near/omni-tests/src/init_transfer.rs`, substituting a sub-unit amount and a trusted relayer caller, then asserting that `sign_transfer` always fails and no recovery call exists. [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-485)
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

**File:** near/omni-bridge/src/lib.rs (L2194-2224)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
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
