Audit Report

## Title
No Cancel Mechanism for Pending NEAR→Foreign Transfers Causes Permanent Fund Loss - (File: `near/omni-bridge/src/lib.rs`)

## Summary
The NEAR omni-bridge contract irrevocably burns or locks user tokens during `init_transfer_internal` before verifying that the token is registered on the destination chain. If `sign_transfer` subsequently panics due to missing `token_id_to_address` or `token_decimals` entries, the transfer is permanently stuck in `pending_transfers` with no user-callable cancel or refund path. A grep across all production source files confirms zero occurrences of any cancel, withdraw, or refund function for pending outbound transfers.

## Finding Description
The exploit path is as follows:

1. A user calls `ft_transfer_call` on a token that is accepted by the bridge (either in `deployed_tokens` or as a native token) but whose address or decimals are not yet registered on the destination chain.

2. The bridge's `ft_on_transfer` → `init_transfer` → `init_transfer_internal` flow executes. At lines 1850–1857, `burn_tokens_if_needed` and `lock_tokens_if_needed` are called unconditionally, committing the user's tokens. The function then returns `U128(0)`, so the token contract retains all tokens (no refund). [1](#0-0) 

3. A trusted relayer calls `sign_transfer`. At lines 462–474, the function calls `get_token_address(destination_chain, token_id)` and panics with `BridgeError::FailedToGetTokenAddress` if the mapping is absent, or panics with `BridgeError::TokenDecimalsNotFound` if decimals are missing. The transaction reverts, but the transfer remains in `pending_transfers` and the tokens remain burned/locked. [2](#0-1) 

4. `sign_transfer` is gated by `#[trusted_relayer]`, so the user cannot self-sign to force completion or trigger any recovery. [3](#0-2) 

5. A grep for `cancel|withdraw_transfer|refund_transfer|cancel_transfer` across `near/omni-bridge/src/**/*.rs` returns zero matches. There is no user-callable escape hatch.

6. The only admin path is `transfer_token_as_dao` (lines 1511–1530), which does not update `pending_transfers` or `locked_tokens`, leaving the bridge in an inconsistent accounting state. Furthermore, for burned (deployed) tokens, the tokens no longer exist on-chain and cannot be recovered even by the DAO. [4](#0-3) 

## Impact Explanation
This matches the Critical allowed impact: **permanent freezing of bridged funds**. For deployed/bridged tokens, `burn_tokens_if_needed` destroys the tokens on NEAR; if the destination-chain registration is never completed, those tokens are unrecoverable. For native tokens, `lock_tokens_if_needed` traps them in the bridge with no user-callable release. In both cases the user suffers an irreversible loss of funds through normal bridge usage. [5](#0-4) 

## Likelihood Explanation
Medium. Any unprivileged user can trigger this by initiating a transfer for a token that is registered on NEAR but whose destination-chain address or decimals entry is absent. This window exists naturally during token onboarding (token deployed on NEAR before its foreign address is registered), after a registration entry is removed, or for any newly supported chain. The user has no on-chain signal that the transfer will fail before committing funds, and cannot self-recover because `sign_transfer` is restricted to trusted relayers. [6](#0-5) 

## Recommendation
1. **Add a pre-check in `init_transfer` or `init_transfer_internal`**: before burning or locking, verify that `get_token_address(destination_chain, token_id)` returns `Some` and that `token_decimals` contains an entry for that address. If either is absent, return the full `amount` immediately so the `ft_transfer_call` refund path is triggered.

2. **Implement a `cancel_transfer` function** callable by the original `sender` (stored in `TransferMessage`): remove the entry from `pending_transfers`, refund storage to the owner, mint back burned tokens (for deployed tokens) or transfer locked tokens back to the sender (for native tokens), and call `revert_lock_actions` to restore `locked_tokens` accounting. [7](#0-6) 

## Proof of Concept
1. Deploy the bridge on a local testnet. Register token `T` in `deployed_tokens` on NEAR but do **not** call the function that populates `token_id_to_address` for chain X.
2. Call `ft_transfer_call` on token `T` with a recipient on chain X and any non-zero amount.
3. Observe that `init_transfer_internal` burns the tokens and stores the `TransferMessage`; `ft_on_transfer` returns `U128(0)`.
4. Have a trusted relayer call `sign_transfer` with the resulting `transfer_id`.
5. Observe the transaction panic with `BridgeError::FailedToGetTokenAddress`.
6. Confirm the transfer remains in `pending_transfers` and the tokens are gone.
7. Confirm no `cancel_transfer` or equivalent function exists in the contract ABI.
8. Tokens are permanently lost. [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-474)
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
```

**File:** near/omni-bridge/src/lib.rs (L1511-1530)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn transfer_token_as_dao(
        &mut self,
        token: AccountId,
        amount: U128,
        recipient: AccountId,
        msg: Option<String>,
    ) -> Promise {
        if let Some(msg) = msg {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(recipient, amount, None, msg)
        } else {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** near/omni-bridge/src/token_lock.rs (L122-142)
```rust
    pub fn revert_lock_actions(&mut self, lock_actions: &[LockAction]) {
        for lock_action in lock_actions {
            match lock_action {
                LockAction::Locked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.unlock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unlocked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.lock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unchanged => {}
            }
        }
    }
```
