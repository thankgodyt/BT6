### Title
Unchecked Return Value of `burn` Cross-Contract Call Enables Token Supply Inflation — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`burn_tokens_if_needed` schedules a cross-contract `burn` call with `.detach()`, permanently discarding the promise result. If the burn fails for any reason, the bridge proceeds as if it succeeded: the `InitTransferEvent` is still emitted, the transfer record is stored, and a relayer can finalize the transfer on the destination chain — minting tokens there while the original tokens remain unburned in the bridge contract.

---

### Finding Description

`burn_tokens_if_needed` is a private helper called in every outbound-transfer path for bridge-deployed tokens: [1](#0-0) 

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)   // 3 TGas
            .burn(amount)
            .detach();                          // result silently discarded
    }
}
```

The `.detach()` call severs the promise chain: NEAR will never surface the outcome of the `burn` call back to the bridge contract. Any failure — out-of-gas, panic inside the token contract, or any future edge case — is silently swallowed.

The function is invoked in four security-critical sites:

**1. `init_transfer_internal` — primary outbound transfer path** [2](#0-1) 

After `burn_tokens_if_needed` returns (without awaiting the burn), the function unconditionally emits `InitTransferEvent` and returns `U128(0)` to `ft_transfer_call`, signalling that all tokens were consumed. If the burn fails, the tokens remain in the bridge contract while the event is on-chain.

**2. `resolve_fast_transfer` — fast-transfer resolution** [3](#0-2) 

The in-code comment reads *"Burn the tokens to ensure the locked tokens are not double-minted"* — explicitly acknowledging that the burn is the guard against double-minting. A silent burn failure removes that guard.

**3. `fast_fin_transfer_to_other_chain` — fast fin-transfer to another chain** [4](#0-3) 

**4. `fin_transfer_send_tokens_callback` — refund path** [5](#0-4) 

The `burn` function on the token contract is straightforward: [6](#0-5) 

It calls `assert_controller()` (checking `predecessor == controller`) and then `internal_withdraw`. While the bridge is the controller, the call can still fail if the bridge contract's balance in the token is zero (e.g., due to a race condition or accounting error), or if the 3 TGas budget is exhausted by the NEAR runtime's cross-contract call overhead in a deeply nested call stack.

The project's own security checklist in `near/CLAUDE.md` explicitly flags this pattern: [7](#0-6) 
> "Check .detach() usage: Detached promises should only be used for non-critical operations"

The burn is unambiguously a critical operation.

---

### Impact Explanation

**Critical — token supply inflation / double-spending of bridged assets.**

For bridge-deployed tokens (e.g., wETH, wSOL minted by the bridge on NEAR), the invariant is: *tokens sent outbound must be burned on NEAR before equivalent tokens are minted on the destination chain*. If the burn silently fails:

- The `InitTransferEvent` is already on-chain.
- A relayer submits the proof to the destination chain and mints `amount` tokens there.
- The original `amount` tokens remain unburned in the bridge contract on NEAR.
- Total circulating supply increases by `amount` — permanent inflation of the bridged token.

For `resolve_fast_transfer`, the same outcome applies: the relayer's fronted tokens are not burned, yet the destination-chain mint has already occurred (or will occur via the stored transfer message), resulting in double-minting of locked tokens.

---

### Likelihood Explanation

The entry point is `ft_transfer_call` on any bridge-deployed token — a fully public, unprivileged call available to any token holder. No special role or permission is required.

The burn failure can be triggered by:
- **Gas exhaustion**: `BURN_TOKEN_GAS` is only 3 TGas. In a deeply nested call (e.g., `ft_transfer_call → ft_on_transfer → init_transfer_internal → burn`), the NEAR runtime's base cross-contract call overhead alone can consume a significant fraction of this budget, leaving insufficient gas for the token contract's execution.
- **Token contract state**: If the bridge's registered balance in the token contract is zero or inconsistent (e.g., due to a prior accounting bug), `internal_withdraw` panics, the burn fails, and `.detach()` hides it.

Because the failure is silent, it may go undetected until the supply discrepancy is noticed on-chain.

---

### Recommendation

Replace `.detach()` with a proper callback that checks the burn result and reverts the transfer if the burn failed:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) -> Option<Promise> {
    if self.is_deployed_token(&token) {
        Some(
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
        )
    } else {
        None
    }
}
```

In `init_transfer_internal`, chain the burn promise and add a callback that panics (causing the entire `ft_transfer_call` to refund) if the burn fails. Similarly, in `resolve_fast_transfer` and `fast_fin_transfer_to_other_chain`, the burn result must be awaited before the transfer record is committed or the event is emitted.

Also increase `BURN_TOKEN_GAS` from 3 TGas to at least 10–15 TGas to provide a safe margin for the cross-contract call overhead.

---

### Proof of Concept

1. Attacker holds `N` units of a bridge-deployed token (e.g., `weth.bridge.near`).
2. Attacker calls `ft_transfer_call(bridge.near, N, msg=InitTransfer{recipient: eth_address, ...})`.
3. Token contract transfers `N` tokens to `bridge.near` and calls `ft_on_transfer`.
4. Bridge calls `init_transfer_internal` → `burn_tokens_if_needed` → schedules `burn(N).detach()`.
5. Due to gas exhaustion or token contract panic, the burn fails — silently.
6. Bridge emits `InitTransferEvent{amount: N, recipient: eth_address}` and returns `U128(0)` to `ft_transfer_call` (no refund).
7. A relayer picks up the event and calls `finTransfer` on the EVM bridge, minting `N` wETH to `eth_address`.
8. Result: `N` wETH exist on Ethereum AND `N` weth tokens remain unburned in `bridge.near` — total supply inflated by `N`. [1](#0-0) [8](#0-7) [9](#0-8)

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L932-938)
```rust
        self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());

        self.lock_tokens_if_needed(
            fast_transfer.get_destination_chain(),
            &fast_transfer.token_id,
            amount_without_fee,
        );
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

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```

**File:** near/CLAUDE.md (L228-228)
```markdown
4. **Check .detach() usage**: Detached promises should only be used for non-critical operations
```
