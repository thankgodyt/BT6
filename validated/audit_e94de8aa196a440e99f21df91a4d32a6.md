### Title
Unchecked Burn Promise Result in `burn_tokens_if_needed` Enables Double-Spending of Bridged Tokens — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`burn_tokens_if_needed` fires a cross-contract burn call with `.detach()`, discarding the promise result entirely. If the burn fails for any reason, the `InitTransferEvent` is still emitted and the transfer proceeds, allowing a relayer to mint tokens on the destination chain while the user's bridged tokens on NEAR remain unburned — a direct double-spend.

---

### Finding Description

In `init_transfer_internal`, when the transferred token is a bridge-deployed (bridged) token, the contract calls `burn_tokens_if_needed` to destroy the tokens held by the bridge before emitting the outbound transfer event: [1](#0-0) 

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();   // ← result is never checked
    }
}
```

The `.detach()` call means the NEAR runtime submits the burn cross-contract call but the current function does **not** wait for its outcome. Execution continues unconditionally: [2](#0-1) 

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(...);
} else { ... }

env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
U128(0)   // ← signals "no refund" regardless of burn outcome
```

The `InitTransferEvent` is logged and `U128(0)` is returned (telling the FT contract to keep the tokens at the bridge) whether or not the burn succeeded. A relayer observing this event will proceed to finalize the transfer on the destination chain, minting tokens there.

The project's own security checklist acknowledges this risk: [3](#0-2) 

> "Check .detach() usage: Detached promises should only be used for non-critical operations."

Burning tokens during an outbound transfer is unambiguously a **critical** operation.

---

### Impact Explanation

If the burn promise fails (see likelihood below), the following state exists simultaneously:

- The bridge holds the bridged tokens on NEAR (they were transferred in via `ft_on_transfer` and never destroyed).
- The `InitTransferEvent` has been emitted on-chain.
- A relayer finalizes the transfer on the destination chain, minting the equivalent native tokens there.

The user ends up with tokens on **both** chains — a classic double-spend. Because bridged tokens are backed 1:1 by locked native tokens on the origin chain, this inflates the circulating supply of the bridged asset and drains the backing reserve.

**Impact class:** Critical — unauthorized minting / double-spending of bridged funds.

---

### Likelihood Explanation

The burn can fail in realistic, attacker-reachable scenarios:

1. **Insufficient static gas**: `BURN_TOKEN_GAS` is a fixed allocation. If the `OmniToken.burn` execution path consumes more gas than allocated (e.g., after a contract upgrade), the burn silently fails while the transfer event is still emitted.
2. **Token contract paused**: If the `OmniToken` contract is paused at the moment of the burn (e.g., during an incident response), the burn call reverts but the transfer event is still emitted.
3. **Reentrancy / state race**: A malicious or buggy token contract that is registered as a deployed token could deliberately cause the burn to fail.

Scenario 1 requires no special privileges — any user initiating an outbound transfer of a bridged token is exposed. Scenario 2 is triggered by normal operational events. Both are realistic.

---

### Recommendation

Replace the fire-and-forget `.detach()` pattern with a chained callback that verifies the burn succeeded before emitting the `InitTransferEvent`. The pattern already used elsewhere in the contract (e.g., `sign_transfer_callback`, `fin_transfer_callback`) should be applied here:

```rust
fn burn_tokens_if_needed(...) -> Promise {
    ext_token::ext(token)
        .with_static_gas(BURN_TOKEN_GAS)
        .burn(amount)
        .then(Self::ext(env::current_account_id())
            .burn_callback(transfer_message, storage_owner))
}
```

The `InitTransferEvent` should only be emitted inside `burn_callback` after confirming the burn succeeded; on failure the transfer should be reverted and the tokens refunded.

---

### Proof of Concept

1. User calls `ft_transfer_call` on a bridge-deployed token, sending `N` tokens to the bridge with `msg` encoding an `InitTransfer` to an EVM destination.
2. Bridge receives tokens via `ft_on_transfer` → `init_transfer` → `init_transfer_internal`.
3. `burn_tokens_if_needed` fires the burn with `.detach()`. Suppose the token contract is paused at this moment — the burn reverts silently.
4. `init_transfer_internal` continues, emits `InitTransferEvent`, returns `U128(0)` (no refund).
5. The bridge still holds the `N` bridged tokens (burn failed, tokens not destroyed).
6. A relayer observes `InitTransferEvent` and calls `finTransfer` on the EVM bridge, minting `N` native tokens for the user on Ethereum.
7. User now holds `N` tokens on Ethereum **and** the bridge holds `N` bridged tokens on NEAR that were never burned — total supply inflated by `N`. [1](#0-0) [4](#0-3)

### Citations

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
