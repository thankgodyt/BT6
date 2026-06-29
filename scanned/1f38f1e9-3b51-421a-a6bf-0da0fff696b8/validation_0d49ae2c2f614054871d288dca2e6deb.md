### Title
`burn_tokens_if_needed` Detached Promise Silently Ignores Burn Failure, Enabling Token Supply Inflation - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`burn_tokens_if_needed` fires a cross-contract `burn` call with `.detach()`, discarding the promise result entirely. If the burn fails for any reason, the bridge has already committed the transfer record and will emit `InitTransferEvent`, causing the destination chain to mint tokens — while the source tokens remain unburned inside the bridge contract. This inflates the total bridged token supply.

---

### Finding Description

In `init_transfer_internal`, after the user's tokens have been received by the bridge via `ft_transfer_call`, the function calls `burn_tokens_if_needed` and then unconditionally emits `InitTransferEvent`: [1](#0-0) 

`burn_tokens_if_needed` is implemented as a fire-and-forget detached promise: [2](#0-1) 

In NEAR's async execution model, `.detach()` means no callback is registered. If the `burn` cross-contract call panics, runs out of its statically allocated `BURN_TOKEN_GAS`, or fails for any other reason, the failure is completely invisible to the calling contract. The `InitTransferEvent` log at line 1863 has already been written, the transfer message is already stored, and the relayer/MPC network will proceed to finalize the transfer on the destination chain. [3](#0-2) 

This is the direct NEAR analog of the Solidity pattern of ignoring a boolean return value from an external call: the external operation (burn) may silently fail while the rest of the protocol logic proceeds as if it succeeded.

---

### Impact Explanation

When the burn fails silently:

1. The bridge contract holds the user's tokens (transferred in via `ft_transfer_call`, with `U128(0)` returned meaning no refund).
2. `InitTransferEvent` is emitted and picked up by the relayer/MPC network.
3. The destination chain finalizes the transfer and mints (or releases) tokens to the recipient.
4. The source bridge-deployed token supply is **not reduced** — the tokens remain locked in the bridge contract.

Result: the total supply of the bridged asset is inflated by the transfer amount. The bridge's escrow accounting is permanently inconsistent. Over repeated occurrences, this enables unbacked token minting across chains.

This falls squarely within: *"Balance manipulation, escrow mis-accounting … that changes user or protocol balances"* and *"unauthorized minting … of bridged funds."*

---

### Likelihood Explanation

The `BURN_TOKEN_GAS` is a static compile-time constant. If the token contract's `burn` implementation consumes more gas than allocated (e.g., due to storage reads, access-control checks, or future upgrades to the token contract), the promise fails silently on every such transfer. A user who understands NEAR's gas model can craft a transaction that exhausts the burn's gas budget while keeping the outer `ft_transfer_call` execution alive, triggering the silent failure path. No privileged access is required — any user who can call `ft_transfer_call` on a bridge-deployed token is a potential trigger.

---

### Recommendation

Replace the detached promise with a chained callback that verifies the burn succeeded before the transfer is considered finalized. The `InitTransferEvent` should only be emitted inside the burn callback, after confirming the burn promise resolved successfully. If the burn fails, the callback should refund the tokens to the sender and remove the transfer message.

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) -> Promise {
    ext_token::ext(token)
        .with_static_gas(BURN_TOKEN_GAS)
        .burn(amount)
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(BURN_CALLBACK_GAS)
                .on_burn_callback(/* transfer_message, sender */)
        )
}
```

The `on_burn_callback` should check `env::promise_result(0)` and revert the transfer (remove message, refund tokens) if the burn failed.

---

### Proof of Concept

1. User calls `ft_transfer_call` on a bridge-deployed NEAR token, sending `N` tokens to the bridge with an `InitTransfer` message targeting an EVM chain.
2. Bridge's `ft_on_transfer` → `init_transfer_internal` is invoked.
3. `burn_tokens_if_needed` schedules a detached `burn(N)` promise with `BURN_TOKEN_GAS`.
4. The burn promise fails (gas exhaustion or token contract panic) — silently, with no callback.
5. `init_transfer_internal` returns `U128(0)` (no refund), keeping `N` tokens in the bridge.
6. `InitTransferEvent` is emitted with the full transfer details.
7. The relayer submits the proof to the EVM `OmniBridge.finTransfer`, which mints `N` tokens to the recipient.
8. Net result: `N` tokens exist on the EVM side, and `N` tokens remain unburned inside the NEAR bridge contract — total supply inflated by `N`. [2](#0-1) [4](#0-3)

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
