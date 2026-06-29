Audit Report

## Title
Fee and Escrow Permanently Lost When `ft_transfer` Fails After Irrevocable State Mutation in `send_fee_internal` — (File: near/omni-bridge/src/lib.rs)

## Summary

In `claim_fee_callback`, `remove_transfer_message` permanently deletes the pending transfer and `send_fee_internal` emits `ClaimFeeEvent` and decrements `locked_tokens` before the `ft_transfer` promise is dispatched. No failure callback is attached to that promise. If `ft_transfer` fails, the fee tokens remain stranded in the bridge's NEP-141 balance with no accounting entry and no recovery path, breaking the `locked_tokens` invariant and permanently losing the relayer fee.

## Finding Description

The call chain in `claim_fee_callback` (line 1068) is:

1. `remove_transfer_message` (line 1094) — permanently removes the entry from `pending_transfers` and credits storage refund to the owner. This state change is committed when `claim_fee_callback` returns.
2. `send_fee_internal` (line 1133 / 2650) — emits `ClaimFeeEvent` (line 2677–2682), calls `unlock_tokens_if_needed` (line 2684) to decrement `locked_tokens`, then dispatches `ft_transfer` (line 2693–2697) with only `.into()` — no `.then(callback)`.

```rust
// lib.rs:2684 — locked_tokens decremented before ft_transfer result is known
self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);

// lib.rs:2693–2697 — no failure callback
ext_token::ext(token)
    .with_static_gas(FT_TRANSFER_GAS)
    .with_attached_deposit(ONE_YOCTO)
    .ft_transfer(fee_recipient, U128(token_fee), None)
    .into()
```

In NEAR's execution model, state mutations from `claim_fee_callback` are committed when the function returns. The `ft_transfer` executes in a subsequent receipt. If it fails (e.g., `fee_recipient` has no storage deposit on the NEP-141 token contract), there is no callback to re-insert the transfer into `pending_transfers` or re-increment `locked_tokens`. The `TransferId` is gone, the event is already logged, and the tokens are stranded.

The correct pattern exists in `submit_transfer_to_btc_connector_callback` (btc.rs line 114–125), which re-inserts the transfer message on failure. That guard is absent here.

## Impact Explanation

This matches the Critical allowed impact: **escrow mis-accounting and fee mis-accounting that changes protocol balances**. Specifically:
- `locked_tokens` is decremented (line 2684) but the actual `ft_transfer` never completes, so the bridge holds tokens it no longer tracks — a broken escrow invariant.
- The fee amount is permanently stranded in the bridge's NEP-141 balance with no accounting entry and no recovery mechanism short of a contract upgrade.
- `ClaimFeeEvent` is emitted and the transfer record is deleted before delivery is confirmed, breaking the protocol's event/state consistency.

## Likelihood Explanation

`claim_fee` is gated by `#[trusted_relayer]` (line 1055), so the caller must be a registered relayer. The `fee_recipient` must equal the caller (lines 1083–1086). The trigger condition — a trusted relayer whose account lacks a storage deposit on the specific bridged NEP-141 token — is operationally plausible for newly listed tokens or tokens the relayer has never interacted with. No adversarial third party is required; the relayer can trigger this accidentally. The condition is repeatable for any token the relayer has not registered storage for.

## Recommendation

Attach a failure callback to the `ft_transfer` promise in `send_fee_internal` for non-deployed tokens. On failure, re-insert the transfer message into `pending_transfers` and re-increment `locked_tokens`. Alternatively, move `remove_transfer_message` and `unlock_tokens_if_needed` into a success callback so state is only mutated after confirmed delivery. `ClaimFeeEvent` should also be emitted only inside the success callback. The BTC path in `submit_transfer_to_btc_connector_callback` (btc.rs lines 114–125) demonstrates the correct rollback pattern and should be replicated here.

## Proof of Concept

1. Deploy the bridge on localnet with a standard NEP-141 token contract.
2. Initiate a cross-chain transfer with a non-zero fee; confirm it appears in `pending_transfers` via `get_transfer_message`.
3. Register a trusted relayer account that has **no storage deposit** on the NEP-141 token contract.
4. Call `claim_fee` from the relayer account with a valid `FinTransfer` proof where `fee_recipient` equals the relayer account.
5. Observe: `claim_fee_callback` succeeds and commits; `ClaimFeeEvent` appears in logs; `get_transfer_message` returns `TransferNotExist`; the relayer's token balance is unchanged (ft_transfer failed); the bridge's `locked_tokens` for that token is decremented — the fee is permanently lost with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
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
