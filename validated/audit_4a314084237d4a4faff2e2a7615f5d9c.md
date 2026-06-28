### Title
Fee Lost on `ft_transfer` Failure After Irrevocable State Mutation in `claim_fee_callback` / `send_fee_internal` — (`near/omni-bridge/src/lib.rs`)

### Summary

`claim_fee_callback` removes the pending transfer and `send_fee_internal` emits `ClaimFeeEvent` and decrements `locked_tokens` **before** the `ft_transfer` promise is dispatched. No failure callback is attached to that promise. If `ft_transfer` fails (e.g., fee_recipient has no storage deposit for the token), the fee tokens remain stranded in the bridge with no recovery path, and the transfer record is gone.

### Finding Description

The call chain is:

```
claim_fee (line 1057)
  → verify_proof
  → claim_fee_callback (line 1068)
      → remove_transfer_message (line 1094)   ← transfer deleted, storage refunded
      → send_fee_internal (line 2133)
          → ClaimFeeEvent emitted (line 2677)  ← event logged
          → unlock_tokens_if_needed (line 2684) ← locked_tokens decremented
          → ext_token::ft_transfer(...).into() (line 2693) ← no .then(callback)
```

`remove_transfer_message` permanently deletes the entry from `pending_transfers` and credits the storage refund to the owner: [1](#0-0) 

`send_fee_internal` emits the event and decrements accounting **before** dispatching the token transfer, and returns the promise with no failure handler: [2](#0-1) 

In NEAR's execution model, state mutations from `claim_fee_callback` are committed when the function returns. The returned `ft_transfer` promise executes in a subsequent receipt. If it fails, there is no `.then(callback)` to revert the deletion or re-credit the fee. The tokens remain in the bridge's NEP-141 balance but are no longer tracked by `locked_tokens`, and the `TransferId` is gone from `pending_transfers` — making recovery impossible without a contract upgrade.

### Impact Explanation

- **Permanent loss of relayer fee**: the fee amount in tokens is stranded in the bridge contract with no accounting entry and no recovery mechanism.
- **Bridge escrow mis-accounting**: `locked_tokens` is decremented (line 2684) but the actual `ft_transfer` never completes, so the bridge holds tokens it no longer tracks.
- **Broken invariant**: `ClaimFeeEvent` is emitted and the transfer is removed before the fee delivery is confirmed.

This matches the Critical scope: *fee mis-accounting and escrow mis-accounting that changes protocol balances*.

### Likelihood Explanation

`claim_fee` is gated by `#[trusted_relayer]` (line 1055), so the caller must be a registered relayer. The fee_recipient must equal the caller (line 1083–1086). The trigger condition — a trusted relayer whose account lacks a storage deposit for the specific bridged token — is operationally plausible, especially for newly listed tokens or tokens the relayer has never interacted with. No adversarial third party is required; the relayer themselves (or any party that can register as a trusted relayer) can trigger this accidentally or deliberately. [3](#0-2) [4](#0-3) 

### Recommendation

Attach a failure callback to the `ft_transfer` promise in `send_fee_internal` for non-deployed tokens. On failure, re-insert the transfer message into `pending_transfers` and re-increment `locked_tokens`. Alternatively, move `remove_transfer_message` and `unlock_tokens_if_needed` into the success callback, so state is only mutated after confirmed delivery. The `ClaimFeeEvent` should also be emitted only inside the success callback.

Compare with the BTC path in `submit_transfer_to_btc_connector_callback`, which correctly re-inserts the transfer on failure: [5](#0-4) 

### Proof of Concept

1. Deploy bridge on localnet with a non-deployed NEP-141 token (e.g., a standard `ft` contract).
2. Initiate a transfer with a non-zero fee; confirm it is in `pending_transfers`.
3. Register a trusted relayer account that has **no storage deposit** on the NEP-141 token contract.
4. Call `claim_fee` from the relayer account with a valid `FinTransfer` proof where `fee_recipient` = relayer.
5. Observe: `claim_fee_callback` succeeds, `ClaimFeeEvent` is in the logs, `get_transfer_message` returns `TransferNotExist`, but the relayer's token balance is unchanged and the bridge's `locked_tokens` for that token is decremented — the fee is permanently lost.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L2194-2210)
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
```

**File:** near/omni-bridge/src/lib.rs (L2676-2697)
```rust
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
```

**File:** near/omni-bridge/src/btc.rs (L110-126)
```rust
    ) -> PromiseOrValue<()> {
        if matches!(call_result, Ok(result) if result.0 > 0) {
            let token_fee = transfer_msg.fee.fee.0;
            self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
        } else {
            let required_storage_balance =
                self.add_transfer_message(transfer_msg, transfer_owner.clone());

            self.update_storage_balance(
                transfer_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            PromiseOrValue::Value(())
        }
    }
```
