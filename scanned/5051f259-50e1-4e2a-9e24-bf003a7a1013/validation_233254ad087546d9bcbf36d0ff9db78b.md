### Title
Unverified Detached Burn Promise in `init_transfer_internal` Allows `InitTransferEvent` Emission Without Confirmed Token Destruction - (File: near/omni-bridge/src/lib.rs)

---

### Summary

`burn_tokens_if_needed` fires the cross-contract `burn` call with `.detach()`, discarding the promise result entirely. `init_transfer_internal` then unconditionally emits `InitTransferEvent` on the very next line. If the burn fails for any reason, the event is still emitted, signalling to the destination chain that tokens were destroyed on NEAR when they were not.

---

### Finding Description

In `near/omni-bridge/src/lib.rs`, `burn_tokens_if_needed` is:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();   // ← result is never observed
    }
}
``` [1](#0-0) 

It is called from `init_transfer_internal`, which immediately emits `InitTransferEvent` after the detached call returns:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
// ...
env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
``` [2](#0-1) 

Because the burn promise is detached, its success or failure has no effect on whether the event is emitted. The NEAR runtime schedules the burn receipt asynchronously; the enclosing `ft_on_transfer` transaction completes and the event is logged before the burn receipt is ever executed.

The same pattern appears in `fin_transfer_send_tokens_callback` (the failed-inbound-transfer refund path), where a detached burn is used to destroy tokens that were minted but rejected by the recipient: [3](#0-2) 

The project's own security checklist in `near/CLAUDE.md` explicitly flags this risk: *"Check .detach() usage: Detached promises should only be used for non-critical operations"* — yet the burn in `init_transfer_internal` is the most critical operation in the outbound flow. [4](#0-3) 

The EVM-side security invariant also states: *"Event–transfer atomicity: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction."* [5](#0-4) 

The NEAR-side `init_transfer_internal` violates this invariant because the burn is asynchronous and unverified.

---

### Impact Explanation

**Outbound path (`init_transfer_internal`):**

1. User calls `ft_transfer_call` on a deployed/bridged NEAR token, transferring `amount` to the bridge.
2. Bridge calls `init_transfer_internal`; `burn_tokens_if_needed` fires a detached burn.
3. `InitTransferEvent` is emitted unconditionally.
4. If the burn receipt fails (gas exhaustion, token contract panic, token paused, etc.), the `amount` tokens remain in the bridge's balance — they are **not** destroyed.
5. A relayer observes the event and submits proof to the destination chain.
6. The destination chain mints `amount` tokens to the recipient.
7. Result: `amount` tokens exist on the destination chain **and** `amount` tokens remain un-burned on NEAR inside the bridge — total cross-chain supply is inflated by `amount`.

**Inbound refund path (`fin_transfer_send_tokens_callback`):**

If the recipient's `ft_on_transfer` rejects the delivery, the bridge mints tokens back to itself and calls `burn_tokens_if_needed` (detached) to destroy them. If that burn fails, the bridge holds minted tokens that should not exist, inflating the deployed token's total supply. [6](#0-5) 

---

### Likelihood Explanation

The burn can fail in realistic, non-admin-controlled scenarios:

- **Gas exhaustion**: `BURN_TOKEN_GAS` is a fixed static allocation. If the token contract's `burn` execution path consumes more gas than allocated (e.g., after an upgrade to `OmniToken`), the receipt fails silently.
- **Token contract panic**: Any unexpected panic inside `OmniToken.burn` (e.g., arithmetic overflow with `overflow-checks = true`, storage corruption) causes the receipt to fail.
- **Token contract paused**: If the deployed token has a pause mechanism and is paused at the moment the burn receipt executes, the burn reverts while the `InitTransferEvent` has already been logged.

The entry path is fully unprivileged: any token holder can call `ft_transfer_call` on a deployed bridge token to trigger `init_transfer_internal`. [7](#0-6) 

---

### Recommendation

Replace the detached burn with an awaited promise and gate the `InitTransferEvent` emission on the burn callback result. Concretely:

1. In `init_transfer_internal`, instead of calling `burn_tokens_if_needed` (detached) and immediately emitting the event, return a `Promise` that chains a callback.
2. In the callback, check the burn result. Only emit `InitTransferEvent` if the burn succeeded; otherwise refund the user and remove the pending transfer message.

This mirrors the pattern already used for `fin_transfer` flows where `send_tokens` is chained to `fin_transfer_send_tokens_callback`.

---

### Proof of Concept

```
1. Deploy a bridged OmniToken T registered in the bridge's `deployed_tokens`.
2. Pause token T (if it has a pause mechanism) or arrange for BURN_TOKEN_GAS to be
   insufficient for T's burn path.
3. Call ft_transfer_call(bridge, amount, init_transfer_msg) on T.
4. init_transfer_internal runs:
     - burn_tokens_if_needed fires detached burn receipt (will fail)
     - InitTransferEvent is emitted immediately
5. Relayer observes InitTransferEvent and submits proof to destination chain.
6. Destination chain mints `amount` tokens to recipient.
7. Burn receipt executes and fails silently (detached — no callback).
8. Bridge still holds `amount` of T; destination chain has minted `amount` of T.
   Total supply across chains is now 2×amount instead of amount.
``` [1](#0-0) [8](#0-7)

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

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
