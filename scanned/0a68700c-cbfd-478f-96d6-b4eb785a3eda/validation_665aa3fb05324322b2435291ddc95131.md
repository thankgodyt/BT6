Looking at the vulnerability class from the external report — a multi-step withdrawal where one step can fail due to external protocol state, permanently locking/losing user funds — I need to find an analog in the NEAR Omni Bridge where a finalization step can fail due to external state, causing bridged funds to be permanently lost.

After reviewing `near/omni-bridge/src/lib.rs`, specifically the fast-transfer finalization flow (`fast_fin_transfer_to_near_callback` → `send_tokens` → `resolve_fast_transfer`), I identified the following:

---

### Title
Unconditional token burn in `resolve_fast_transfer` causes permanent loss of relayer funds when recipient token transfer fails — (File: `near/omni-bridge/src/lib.rs`)

### Summary
In `resolve_fast_transfer`, `burn_tokens_if_needed` is called unconditionally before checking whether the `send_tokens` call to the recipient succeeded. If `send_tokens` fails due to an external state condition (e.g., token contract paused between storage-deposit and transfer, or recipient blacklisted on the token contract), the relayer's bridged tokens are permanently burned without the recipient ever receiving them.

### Finding Description
In `fast_fin_transfer_to_near_callback`, after the storage-deposit check passes, `send_tokens` is called to forward tokens to the NEAR recipient, and `resolve_fast_transfer` is chained as its callback: [1](#0-0) 

Inside `resolve_fast_transfer`, the comment explicitly states the intent — burn the relayer's bridged tokens to prevent double-minting when the original cross-chain transfer is later finalized. However, this burn is performed **unconditionally**, before any check of whether `send_tokens` actually succeeded: [2](#0-1) 

The burn at line 904 fires regardless of the promise result from `send_tokens`. If `send_tokens` fails (token contract paused, recipient blacklisted, gas exhaustion), the relayer's tokens are burned and the recipient receives nothing.

For the `ft_transfer` path (`is_ft_transfer_call = false`): `is_refund_required` returns `false`, so `U128(0)` is returned — no refund, fast-transfer record stays, relayer's tokens are gone.

For the `ft_transfer_call` path (`is_ft_transfer_call = true`): `is_refund_required` returns `true` on failure, so `amount` is returned as the refund signal to the NEP-141 token contract. But the bridge already burned those tokens, so the token contract's attempt to transfer `amount` back to the relayer from the bridge's balance will fail — the bridge no longer holds them.

In both paths, the relayer permanently loses their bridged tokens.

### Impact Explanation
Permanent loss of bridged funds. A relayer who provides liquidity for a fast transfer loses their bridged tokens if the downstream `ft_transfer`/`ft_transfer_call` to the recipient fails due to any external state condition on the token contract. The tokens are burned on NEAR, the recipient receives nothing, and there is no recovery path because the burn is irreversible and the fast-transfer record either stays (blocking re-execution) or is removed (preventing any retry).

### Likelihood Explanation
Low-to-medium. The `check_storage_balance_result` guard in `fast_fin_transfer_to_near_callback` (line 845–848) eliminates the most common failure cause (missing storage registration). However, the token transfer can still fail if: (a) the token contract is paused in the window between the storage-deposit promise and the `ft_transfer` promise, (b) the recipient is blacklisted at the token-contract level, or (c) gas is exhausted during the `ft_transfer` call. All three are externally reachable conditions not controlled by the bridge contract. [3](#0-2) 

### Recommendation
Check the promise result of `send_tokens` inside `resolve_fast_transfer` before calling `burn_tokens_if_needed`. Only burn if the transfer succeeded. If the transfer failed, skip the burn and return the full `amount` as refund so the NEP-141 token contract can restore the relayer's balance. To prevent double-minting on later finalization of the original transfer, the fast-transfer record must be kept (not removed) in the failure case, and the finalization path must detect and handle the outstanding fast-transfer record appropriately.

### Proof of Concept
1. A bridged token contract (e.g., an EVM-origin token deployed on NEAR) is paused by its admin between two NEAR blocks.
2. A relayer calls `ft_on_transfer` on that token contract with a `FastFinTransferMsg` targeting a NEAR recipient.
3. `fast_fin_transfer` → `fast_fin_transfer_to_near_callback` executes; the storage-deposit check passes.
4. `send_tokens` issues an `ft_transfer` cross-contract call; the token contract is paused, so the call fails.
5. `resolve_fast_transfer` fires as the callback.
6. `burn_tokens_if_needed` (line 904) burns the relayer's bridged tokens held by the bridge contract.
7. For the `ft_transfer` path: `is_refund_required(false)` → `false`; `U128(0)` is returned; no refund is issued; the fast-transfer record remains; the relayer's tokens are permanently gone.
8. For the `ft_transfer_call` path: `is_refund_required(true)` → `true`; `amount` is returned as refund signal; the token contract attempts `ft_transfer(relayer, amount)` from the bridge's balance, but the bridge burned those tokens, so the refund transfer fails; the relayer's tokens are permanently gone.

### Citations

**File:** near/omni-bridge/src/lib.rs (L844-848)
```rust
    ) -> Promise {
        require!(
            Self::check_storage_balance_result(0),
            BridgeError::StorageRecipientOmitted.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L877-892)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            recipient,
            amount_without_fee,
            &fast_transfer.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_FAST_TRANSFER_GAS)
                .resolve_fast_transfer(
                    &fast_transfer.token_id,
                    &fast_transfer.id(),
                    amount_without_fee,
                    !fast_transfer.msg.is_empty(),
                ),
        )
```

**File:** near/omni-bridge/src/lib.rs (L896-912)
```rust
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
