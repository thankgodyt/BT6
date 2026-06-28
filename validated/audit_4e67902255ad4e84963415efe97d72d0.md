### Title
Detached `burn_tokens_if_needed` Promise Silently Ignores Burn Failures, Enabling Token Supply Inflation - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`burn_tokens_if_needed` fires the cross-contract `burn()` call with `.detach()`, discarding the promise result entirely. When called during `init_transfer_internal`, the `InitTransferEvent` is emitted and the MPC signer proceeds to mint/unlock tokens on the destination chain regardless of whether the burn on NEAR actually succeeded. A failed burn leaves the original tokens inside the bridge contract while new tokens are created on the destination chain, inflating total supply.

### Finding Description

`burn_tokens_if_needed` is a private helper that destroys deployed (omni-bridge-minted) tokens when they leave NEAR: [1](#0-0) 

The call to `burn()` is `.detach()`-ed, meaning its success or failure is never observed by the bridge contract. This helper is invoked in two security-critical paths:

**Path 1 — `init_transfer_internal` (outbound transfer initiation):** [2](#0-1) 

The burn is fired and immediately forgotten. The function then unconditionally emits `InitTransferEvent`, which triggers the MPC signing pipeline to release/mint tokens on the destination chain.

**Path 2 — `fin_transfer_send_tokens_callback` (failed inbound transfer rollback):** [3](#0-2) 

When an inbound `fin_transfer` fails (recipient rejected tokens), the bridge should burn the already-minted tokens. A silent burn failure leaves those minted tokens in circulation while the transfer is recorded as failed.

The project's own security checklist explicitly flags this pattern: [4](#0-3) 

### Impact Explanation

**Path 1 (critical):** If the burn fails during `init_transfer_internal`, the bridge holds the user's tokens (they were transferred in via `ft_transfer_call` and never destroyed) while simultaneously emitting `InitTransferEvent`. The MPC signer, observing only the event, signs a transaction to mint/unlock an equivalent amount on the destination chain. The attacker ends up with tokens on the destination chain AND the bridge retains the original tokens — a direct double-spend / supply inflation of deployed omni-bridge tokens.

**Path 2 (high):** A failed burn during rollback leaves minted tokens permanently in circulation even though the transfer was recorded as failed, inflating the token supply without a corresponding locked/burned counterpart on the source chain.

### Likelihood Explanation

An unprivileged user initiates the attack by calling `ft_transfer_call` on a deployed omni-bridge token. In NEAR's gas model, the gas allocated to `ft_on_transfer` is fixed by the token contract; the detached `burn` promise consumes whatever gas remains after the synchronous body of `ft_on_transfer` completes. An attacker who supplies a total gas budget that is sufficient for `ft_on_transfer` to reach the `InitTransferEvent` log but insufficient for the detached `burn` promise to execute will trigger the silent failure. All gas constants are public and deterministic, making the required budget calculable off-chain. No privileged role or key compromise is required.

### Recommendation

Replace the fire-and-forget pattern with an awaited promise chain. The burn result must be checked before emitting `InitTransferEvent`. If the burn fails, the transfer should be reverted and the tokens returned to the sender (i.e., `ft_on_transfer` should return the full `amount` as the refund value). Concretely:

```rust
// Instead of:
ext_token::ext(token).with_static_gas(BURN_TOKEN_GAS).burn(amount).detach();
// Use an awaited callback that panics or refunds on burn failure.
```

The project's own checklist already states: *"Detached promises should only be used for non-critical operations."* Burning tokens to prevent double-spend is a critical operation and must not be detached.

### Proof of Concept

1. Attacker holds `N` units of a deployed omni-bridge token (e.g., `omni-usdc.near`).
2. Attacker calls `ft_transfer_call` on `omni-usdc.near` targeting the bridge, with a carefully chosen gas budget: enough for `ft_on_transfer` to complete through `env::log_str(InitTransferEvent)` but below `BURN_TOKEN_GAS` remaining for the detached promise.
3. `ft_on_transfer` returns `U128(0)` (no refund); the token contract's callback does not refund the attacker.
4. The detached `burn` promise executes with insufficient gas and fails silently — bridge now holds `N` tokens.
5. `InitTransferEvent` was already emitted; MPC signer signs a transaction minting `N` tokens on the destination chain.
6. Attacker receives `N` tokens on the destination chain. Bridge holds `N` tokens on NEAR. Net result: `N` tokens created from nothing.

### Citations

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

**File:** near/CLAUDE.md (L228-228)
```markdown
4. **Check .detach() usage**: Detached promises should only be used for non-critical operations
```
