### Title
Unverified `burn` Promise in `burn_tokens_if_needed` Allows Token Supply Inflation on Cross-Chain Transfer - (`File: near/omni-bridge/src/lib.rs`)

### Summary
`burn_tokens_if_needed` fires a cross-contract `burn()` call with `.detach()`, meaning the result is never checked. If the burn fails for any reason, the bridge proceeds as if it succeeded: the `InitTransferEvent` is emitted, the destination chain mints tokens to the recipient, but the NEAR-side deployed tokens are never destroyed. This inflates the total cross-chain token supply.

### Finding Description

In `near/omni-bridge/src/lib.rs`, the helper `burn_tokens_if_needed` is defined as:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();   // ← result never observed
    }
}
``` [1](#0-0) 

This function is called inside `init_transfer_internal`, which is the critical path executed when a user initiates a cross-chain transfer of a bridge-deployed NEP-141 token from NEAR:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(...);
}
// ...
env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
U128(0)
``` [2](#0-1) 

The `InitTransferEvent` log is emitted unconditionally after the detached burn, regardless of whether the burn promise succeeds or fails. A relayer picks up this event, calls `sign_transfer`, the MPC signs the payload, and the destination chain's `finTransfer` mints tokens to the recipient.

The same unverified pattern appears in `fin_transfer_send_tokens_callback` (the refund path when a `fin_transfer` to NEAR fails) and in `resolve_fast_transfer`: [3](#0-2) [4](#0-3) 

The project's own security checklist acknowledges the risk: *"Check .detach() usage: Detached promises should only be used for non-critical operations."* The burn of bridged tokens is not a non-critical operation — it is the mechanism that prevents supply inflation. [5](#0-4) 

### Impact Explanation

When `burn_tokens_if_needed` is called during `init_transfer_internal` and the burn promise fails silently:

1. The user's tokens were already transferred to the bridge via `ft_transfer_call` (they are in the bridge's account).
2. The bridge returns `U128(0)` from `ft_on_transfer`, so the token contract keeps the tokens at the bridge.
3. The detached burn fires but fails — the bridge's balance of the deployed token is **not reduced**.
4. `InitTransferEvent` is emitted anyway.
5. The relayer finalizes the transfer on the destination chain, minting tokens to the recipient.

Result: the destination chain has minted new tokens, but the NEAR-side supply was not reduced. The bridge holds "ghost" tokens that should not exist. Total cross-chain supply is inflated. These ghost tokens at the bridge can later be transferred out to a NEAR recipient via a legitimate `fin_transfer` for the same token, effectively double-spending the same token units.

This is a **token supply mis-accounting / escrow mis-accounting** impact matching the allowed scope.

### Likelihood Explanation

The burn can fail due to:
- **Insufficient `BURN_TOKEN_GAS`**: If the deployed token contract's `burn` function consumes more gas than the static allocation, the promise panics silently. Gas constants are fixed at compile time and cannot adapt to token contract complexity.
- **Token contract panic**: Any unexpected panic in the token's `burn` implementation (e.g., storage exhaustion, arithmetic overflow in a non-standard token) causes silent failure.

Any user initiating a transfer of a bridge-deployed token from NEAR is on the vulnerable code path. No special role or privilege is required.

### Recommendation

Replace the fire-and-forget `.detach()` pattern with a chained callback that verifies the burn succeeded before emitting `InitTransferEvent`. The `InitTransferEvent` log (and the transfer message storage) must only be committed after confirming the burn promise succeeded. If the burn fails, the transfer message should be removed and the tokens refunded to the sender (return `transfer_message.amount` from `ft_on_transfer`).

```rust
// Instead of:
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
// ... unconditionally emit event

// Use a chained callback:
ext_token::ext(token_id)
    .with_static_gas(BURN_TOKEN_GAS)
    .burn(transfer_message.amount)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(INIT_TRANSFER_CONFIRM_GAS)
            .init_transfer_burn_callback(transfer_message, storage_owner),
    )
```

The callback should check `env::promise_result(0)` and only emit the event and return `U128(0)` on success; on failure it should remove the transfer message and return the full amount (triggering a refund).

### Proof of Concept

1. Deploy a bridge-deployed NEP-141 token via the bridge's token deployer.
2. Arrange for the token's `burn` function to consume slightly more gas than `BURN_TOKEN_GAS` (e.g., by adding storage operations in a custom token, or by triggering the condition naturally under load).
3. Call `ft_transfer_call(bridge, amount, init_transfer_msg)` on the token.
4. The bridge's `ft_on_transfer` fires the detached burn (which fails due to gas exhaustion), emits `InitTransferEvent`, and returns `U128(0)`.
5. The token contract keeps the tokens at the bridge (not refunded to sender).
6. A relayer calls `sign_transfer`; MPC signs; destination chain calls `finTransfer` and mints `amount` tokens to the recipient.
7. Observe: recipient has tokens on the destination chain, and the bridge holds `amount` of the deployed token on NEAR that was never burned — total supply is inflated by `amount`.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1700-1718)
```rust
        let token = self.get_token_id(&transfer_message.token);

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

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L1895-1912)
```rust
                (status.relayer.clone(), String::new(), status.relayer)
            }
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
        };

        let mut storage_deposit_action_index: usize = 0;
        require!(
            Self::check_storage_balance_result(
                (storage_deposit_action_index + 1)
                    .try_into()
                    .near_expect(BridgeError::Cast)
            ) && storage_deposit_actions[storage_deposit_action_index].account_id == recipient
                && storage_deposit_actions[storage_deposit_action_index].token_id == token,
            BridgeError::StorageRecipientOmitted.as_ref()
```

**File:** near/CLAUDE.md (L228-228)
```markdown
4. **Check .detach() usage**: Detached promises should only be used for non-critical operations
```
