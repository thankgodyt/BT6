### Title
Unchecked External Burn Call via `.detach()` Enables Token Supply Inflation - (`near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR Omni Bridge fires cross-contract `burn` calls using `.detach()`, discarding the promise result entirely. If the burn fails for any reason, the bridge still emits `InitTransferEvent` (or `FastTransferEvent`), causing relayers to mint tokens on the destination chain while the source bridge tokens remain un-burned — inflating total supply across chains.

---

### Finding Description

`burn_tokens_if_needed` is the sole mechanism for destroying bridge-deployed tokens on the NEAR side before a cross-chain transfer is finalized. It is called in at least three critical paths:

1. `init_transfer_internal` — the normal user-initiated transfer path
2. `fast_fin_transfer_to_other_chain` — the fast-transfer path
3. `resolve_fast_transfer` — the fast-transfer resolution callback

In all three cases the burn is scheduled with `.detach()`: [1](#0-0) 

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();   // ← result is never observed
    }
}
```

`BURN_TOKEN_GAS` is only **3 TGas**: [2](#0-1) 

After the detached burn is scheduled, `init_transfer_internal` unconditionally emits `InitTransferEvent`: [3](#0-2) 

The event emission and state mutation (transfer message stored, nonce incremented) happen in the same execution frame as the detached burn, so they are committed to state regardless of whether the burn promise later succeeds or fails.

The same pattern appears in `fast_fin_transfer_to_other_chain`: [4](#0-3) 

And in `resolve_fast_transfer`: [5](#0-4) 

This is the direct NEAR analog of the Solidity `checkSuccess` pattern: an external call whose return value / success status is silently discarded, with protocol state advancing as if the call succeeded.

---

### Impact Explanation

If the detached `burn` promise fails (gas exhaustion at 3 TGas, token contract panic, or any other revert):

- The `InitTransferEvent` / `FastTransferEvent` is already on-chain and immutable.
- Relayers observe the event and finalize the transfer on the destination chain, minting or unlocking the full `amount` there.
- The source bridge tokens are **not** destroyed; they remain in the bridge contract's balance.
- Total circulating supply of the bridged token increases by `amount` — a permanent, cross-chain double-spend / supply inflation.

This matches the **Critical** impact class: *escrow mis-accounting / balance manipulation that changes user or protocol balances*.

---

### Likelihood Explanation

- 3 TGas is an extremely tight budget for a cross-contract call. NEAR's base cross-contract call overhead alone consumes gas, and any non-trivial token contract logic (storage writes, event emission) can push the actual cost above this ceiling.
- A user initiating a transfer via `ft_transfer_call` is an unprivileged, publicly reachable entry point — no special role is required.
- The failure is silent: no on-chain error is surfaced, no retry mechanism exists, and the `InitTransferEvent` is already emitted before the burn result could ever be observed.
- The condition (burn out-of-gas) is deterministic and reproducible once identified, making it reliably exploitable.

---

### Recommendation

1. **Short term:** Replace `.detach()` with a chained callback that checks the burn result before emitting `InitTransferEvent`. If the burn fails, the callback must revert the stored transfer message and return the tokens to the sender.
2. **Short term:** Increase `BURN_TOKEN_GAS` to a value that covers realistic bridge-token burn execution (at minimum 10–15 TGas).
3. **Long term:** Audit every `.detach()` call site in the bridge for similar fire-and-forget patterns on state-critical operations, and replace them with result-checked promise chains.

---

### Proof of Concept

1. User holds `N` units of a bridge-deployed token (e.g., `weth.omni.near`).
2. User calls `ft_transfer_call` on the token contract, transferring `N` tokens to the bridge with a valid `InitTransferMsg` targeting an EVM chain.
3. The bridge's `ft_on_transfer` callback runs `init_transfer_internal`, which:
   - Stores the transfer message (state committed).
   - Calls `burn_tokens_if_needed` → schedules `burn(N)` with 3 TGas and `.detach()`.
   - Emits `InitTransferEvent` (state committed).
4. The detached burn promise executes but fails (e.g., 3 TGas is insufficient for the token contract's burn logic). No callback exists to observe this failure.
5. A relayer observes `InitTransferEvent` and calls `finTransfer` on the EVM `OmniBridge`, which mints `N` tokens to the user's EVM address.
6. The source `N` tokens were never burned — they remain in the bridge contract.
7. Total supply of the bridged token is now inflated by `N` units, and the user holds tokens on both chains.

### Citations

**File:** near/omni-bridge/src/lib.rs (L72-72)
```rust
const BURN_TOKEN_GAS: Gas = Gas::from_tgas(3);
```

**File:** near/omni-bridge/src/lib.rs (L903-911)
```rust
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
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
