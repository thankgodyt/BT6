### Title
Detached `burn` Call in `init_transfer_internal` Emits `InitTransferEvent` Without Guaranteed Token Destruction — (`near/omni-bridge/src/lib.rs`)

### Summary
`burn_tokens_if_needed` fires a cross-contract `burn` call with `.detach()`, meaning its success is never verified. Because `InitTransferEvent` is emitted in the same receipt — before the burn receipt executes — a burn failure is silently ignored while the event is already on-chain, enabling relayers to mint tokens on the destination chain without the corresponding NEAR-side supply being destroyed.

### Finding Description
`burn_tokens_if_needed` is a helper that issues a cross-contract `burn` call on a bridge-deployed token:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)   // only 3 TGas
            .burn(amount)
            .detach();                          // result never checked
    }
}
``` [1](#0-0) 

`BURN_TOKEN_GAS` is set to only 3 TGas: [2](#0-1) 

This helper is called inside `init_transfer_internal`, which then immediately emits `InitTransferEvent` in the same receipt:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
// ...
env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
U128(0)
``` [3](#0-2) 

In NEAR's execution model, `.detach()` schedules the burn as a separate receipt that runs **after** the current function returns. The `env::log_str` call (which emits `InitTransferEvent`) executes in the current receipt. Therefore:

1. `InitTransferEvent` is committed to the blockchain log.
2. The burn receipt runs later and may fail (e.g., gas exhaustion with only 3 TGas, a panicking token contract, or a future contract upgrade).
3. The burn failure is silently discarded — no callback, no revert of the parent receipt.

The same structural flaw exists in `fin_transfer_send_tokens_callback` for the refund path: [4](#0-3) 

The project's own security checklist explicitly flags this pattern: *"Detached promises should only be used for non-critical operations."* [5](#0-4) 

### Impact Explanation
If the detached `burn` receipt fails after `InitTransferEvent` has been emitted:

- The user's tokens are **not** destroyed on NEAR (they remain in the bridge contract's balance).
- Relayers observe the `InitTransferEvent` and mint the equivalent amount on the destination chain.
- The result is **token supply inflation / double-spending**: the same economic value exists simultaneously on NEAR (un-burned, held by the bridge) and on the destination chain (freshly minted).

This matches the critical impact class: *"unauthorized minting or balance manipulation that changes user or protocol balances."*

### Likelihood Explanation
The burn should succeed under normal conditions because the bridge contract is the registered controller of deployed tokens and holds the transferred balance. However, the 3 TGas gas budget is tight for any token with non-trivial `burn` logic, and any future token contract upgrade that adds hooks or storage operations could push the call over the limit. Because the failure is silent and the event is already emitted, there is no on-chain signal that anything went wrong, making detection and recovery difficult.

### Recommendation
Replace the detached burn with a chained callback that verifies success before emitting `InitTransferEvent`:

```rust
ext_token::ext(token_id.clone())
    .with_static_gas(BURN_TOKEN_GAS)
    .burn(transfer_message.amount)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(INIT_TRANSFER_EMIT_GAS)
            .init_transfer_emit_callback(transfer_message, storage_owner),
    )
```

Move the `env::log_str(InitTransferEvent …)` call into the callback, and revert (refund the user) if the burn promise failed. Also increase `BURN_TOKEN_GAS` to at least 5–10 TGas to match the budget used for comparable token operations (`MINT_TOKEN_GAS` is already 5 TGas).

### Proof of Concept

1. Deploy a bridge-deployed `omni-token` on NEAR testnet.
2. Call `ft_transfer_call(bridge, 1000, init_transfer_msg)` as a normal user.
3. Inside `ft_on_transfer` → `init_transfer_internal`:
   - `burn_tokens_if_needed` schedules a detached burn receipt with 3 TGas.
   - `InitTransferEvent` is emitted in the current receipt.
   - `ft_on_transfer` returns `U128(0)` — tokens are not refunded to the user.
4. Simulate burn receipt failure (e.g., by temporarily upgrading the token contract to a version whose `burn` panics, or by exhausting the 3 TGas budget with a heavier implementation).
5. Observe: the burn receipt fails silently; the bridge contract retains the 1000 tokens.
6. A relayer observing `InitTransferEvent` calls `finTransfer` on the EVM side, minting 1000 tokens to the destination recipient.
7. Result: 1000 tokens exist on the destination chain **and** 1000 tokens remain un-burned in the NEAR bridge contract — supply is inflated by 1000. [1](#0-0) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L72-72)
```rust
const BURN_TOKEN_GAS: Gas = Gas::from_tgas(3);
```

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
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

**File:** near/CLAUDE.md (L228-228)
```markdown
4. **Check .detach() usage**: Detached promises should only be used for non-critical operations
```
