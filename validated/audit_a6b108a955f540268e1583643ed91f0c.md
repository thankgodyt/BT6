### Title
Unchecked Cross-Contract Burn/Mint Return Values Allow Silent Failure and Escrow Mis-Accounting - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`burn_tokens_if_needed` fires the cross-contract `burn` call with `.detach()`, discarding the result entirely. `init_transfer_internal` calls this function and then unconditionally emits `InitTransferEvent`. If the burn silently fails, the bridge emits a valid transfer event while the tokens remain un-burned at the bridge contract, allowing relayers to finalize on the destination chain and inflate the bridged token supply. The same pattern recurs in `fin_transfer_send_tokens_callback` for both the fee-mint and the refund-burn paths.

---

### Finding Description

**Root cause 1 — unchecked burn in `init_transfer_internal`**

`burn_tokens_if_needed` (lines 1806–1813) issues the cross-contract `burn` call with `.detach()`:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();          // ← result never observed
    }
}
```

`init_transfer_internal` (lines 1850–1863) calls this and then unconditionally emits the transfer event:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);  // detached
// ...
env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
// emitted regardless of burn outcome
```

If the detached burn promise fails (e.g., `BURN_TOKEN_GAS` is insufficient, or the token contract panics), the bridge contract retains the deposited tokens while the `InitTransferEvent` is already on-chain. Relayers pick up the event and finalize on the destination chain, minting an equivalent amount there. The bridge token supply is now inflated: the original tokens sit un-burned at the bridge contract and an equal amount exists on the destination chain.

**Root cause 2 — unchecked mint/burn in `fin_transfer_send_tokens_callback`**

In the success path (lines 1721–1742), fee minting and fee transfer are both detached:

```rust
ext_token::ext(token)
    .with_static_gas(MINT_TOKEN_GAS)
    .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
    .detach();   // ← fee mint result never checked

ext_token::ext(native_token_id)
    .with_static_gas(MINT_TOKEN_GAS)
    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
    .detach();   // ← native fee mint result never checked
```

In the refund path (lines 1702–1710), the burn that is supposed to undo a failed `ft_transfer_call` mint is also detached via `burn_tokens_if_needed`. If this burn fails, the tokens minted to the bridge contract during `send_tokens` remain un-burned, inflating the deployed token supply while the transfer is removed from storage and marked failed.

---

### Impact Explanation

- **Escrow mis-accounting / supply inflation**: A silent burn failure in `init_transfer_internal` causes the bridge to hold tokens that should have been destroyed while simultaneously authorizing their creation on the destination chain. The total cross-chain supply of the bridged token exceeds the amount that was legitimately locked or burned on NEAR.
- **Fee loss**: Silent mint failure in the success path of `fin_transfer_send_tokens_callback` means the relayer/fee recipient is never compensated, even though the transfer is marked finalized and the nonce is consumed.
- **Refund-path supply inflation**: Silent burn failure in the refund path leaves extra tokens at the bridge contract, permanently inflating the deployed token supply.

---

### Likelihood Explanation

The burn in `init_transfer_internal` is called with a fixed `BURN_TOKEN_GAS` budget. If that budget is ever insufficient for the actual execution of `OmniToken::burn` (which calls `internal_withdraw` and may trigger storage writes), the promise fails silently. Any future change to the token contract that increases its gas cost, or any edge case in the NEAR runtime gas schedule, can trigger this. The path is reachable by any unprivileged user who calls `ft_transfer_call` on a deployed bridge token targeting the bridge contract.

---

### Recommendation

Replace all `.detach()` calls on security-critical burn and mint operations with chained callbacks that verify the promise result and panic (reverting state) on failure:

```rust
// Instead of:
ext_token::ext(token)
    .with_static_gas(BURN_TOKEN_GAS)
    .burn(amount)
    .detach();

// Use:
ext_token::ext(token)
    .with_static_gas(BURN_TOKEN_GAS)
    .burn(amount)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(CALLBACK_GAS)
            .on_burn_callback(),
    );

// In the callback:
#[private]
pub fn on_burn_callback(&mut self) {
    require!(
        env::promise_result_checked(0, MAX_RESULT).is_ok(),
        "burn failed"
    );
}
```

For `init_transfer_internal`, the `InitTransferEvent` must only be emitted inside the burn callback after confirming success. For `fin_transfer_send_tokens_callback`, fee mints must be chained and verified before the transfer is considered finalized.

---

### Proof of Concept

1. Attacker holds bridge tokens (e.g., `wETH.omni.near`) on NEAR.
2. Attacker calls `ft_transfer_call(omni_bridge, 1000, ...)` on the bridge token.
3. Bridge's `ft_on_transfer` → `init_transfer_internal` is invoked.
4. `burn_tokens_if_needed` fires a detached burn with `BURN_TOKEN_GAS`.
5. If the burn promise fails (gas exhaustion or token contract panic), the bridge contract retains 1000 tokens.
6. `InitTransferEvent` is emitted unconditionally at line 1863.
7. A relayer observes the event and calls `fin_transfer` on the EVM bridge, minting 1000 tokens to the attacker's EVM address.
8. Result: attacker holds 1000 tokens on EVM; bridge contract holds 1000 un-burned tokens on NEAR — total supply inflated by 1000. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L1721-1742)
```rust
            if transfer_message.fee.fee.0 > 0 {
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
            }

            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
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

**File:** near/omni-bridge/src/lib.rs (L1850-1863)
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
```
