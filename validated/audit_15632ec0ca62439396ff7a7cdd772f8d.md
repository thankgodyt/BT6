Audit Report

## Title
Unconditional `burn_tokens_if_needed` in `resolve_fast_transfer` Enables Double-Minting of Bridged Tokens — (File: `near/omni-bridge/src/lib.rs`)

## Summary

In `resolve_fast_transfer`, `burn_tokens_if_needed` fires a detached (fire-and-forget) cross-contract burn call unconditionally before the refund branch is evaluated. When a recipient rejects a fast transfer (returning all tokens from `ft_on_transfer`), `is_refund_required` returns `true`, the fast-transfer record is erased, and `amount_without_fee` is returned to the relayer. The token contract then drains the bridge's balance to only `fee` tokens before the detached burn executes, causing the burn to fail silently. A subsequent `fin_transfer` call with the original proof finds no fast-transfer record and mints `amount_without_fee` tokens for the original recipient a second time, while the relayer already holds their `amount_without_fee` refund — inflating the bridged-token supply by `amount_without_fee` per cycle.

## Finding Description

**Root cause — `resolve_fast_transfer` (lines 895–912):**

`burn_tokens_if_needed` is called unconditionally before the `is_refund_required` branch:

```rust
pub fn resolve_fast_transfer(...) -> U128 {
    self.burn_tokens_if_needed(token_id.clone(), amount); // always fires

    if Self::is_refund_required(is_ft_transfer_call) {
        self.remove_fast_transfer(fast_transfer_id);
        amount  // refund to relayer
    } else {
        U128(0)
    }
}
``` [1](#0-0) 

**`burn_tokens_if_needed` is detached (lines 1806–1813):**

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach(); // failure is silent
    }
}
``` [2](#0-1) 

**`is_refund_required` semantics (lines 1784–1804):**

The function reads the result of the inner `send_tokens` promise (which is `ft_transfer_call`). In NEAR's NEP-141, `ft_transfer_call` returns the amount *used* by the receiver (= transferred − refunded). If the recipient rejects all tokens, `ft_transfer_call` returns 0 (0 tokens used), so `amount.0 == 0` evaluates to `true` and a refund is required. [3](#0-2) 

**Token balance trace when recipient rejects tokens:**

1. Relayer deposits `fast_transfer.amount` = `fee + amount_without_fee` into bridge.
2. Bridge calls `ft_transfer_call(recipient, amount_without_fee, msg)` via `send_tokens`.
3. Recipient's `ft_on_transfer` returns `amount_without_fee` (reject). Token contract refunds `amount_without_fee` back to bridge. Bridge holds `fee + amount_without_fee`.
4. `resolve_fast_transfer` executes:
   - Schedules detached burn of `amount_without_fee`.
   - `is_refund_required` → `true`.
   - `remove_fast_transfer` erases the record.
   - Returns `amount_without_fee`.
5. Token contract processes bridge's `ft_on_transfer` return value: transfers `amount_without_fee` from bridge → relayer. Bridge holds `fee`.
6. Detached burn executes: tries to burn `amount_without_fee` from bridge, but bridge only holds `fee` < `amount_without_fee` → `internal_withdraw` panics → burn fails silently.

**Double-minting via `fin_transfer` (lines 1888–1902):**

When `fin_transfer` is called with the original proof, `process_fin_transfer_to_near` calls `get_fast_transfer_status`, which returns `None` (record was erased in step 4). The `None` branch mints/unlocks `amount_without_fee` tokens for the original recipient:

```rust
None => (
    recipient,
    transfer_message.msg.clone(),
    predecessor_account_id.clone(),
),
``` [4](#0-3) 

`add_fin_transfer` prevents replay of `fin_transfer` itself but does not guard against the case where the fast-transfer record was already removed by the refund path. [5](#0-4) 

The exploit requires `msg` to be non-empty (so `is_ft_transfer_call = !fast_transfer.msg.is_empty()` is `true`), which is a realistic condition for DeFi-integrated cross-chain transfers. [6](#0-5) 

## Impact Explanation

This is a critical unauthorized minting / balance manipulation vulnerability. For every deployed (bridged) token, an attacker-controlled NEAR recipient contract can cause the bridge to issue `amount_without_fee` extra tokens per exploit cycle. The bridge's invariant — minted supply on NEAR equals locked supply on the source chain — is permanently broken. The inflated tokens are fully fungible and can be transferred or bridged back, draining the source-chain escrow.

## Likelihood Explanation

No privileged access, key compromise, or collusion is required. The attacker only needs to:
1. Initiate a transfer on any supported source chain to a NEAR recipient address they control (a normal user-deployable contract whose `ft_on_transfer` returns the full amount).
2. Wait for any active trusted relayer to perform a fast transfer (relayers are incentivized by the fee).
3. Have their recipient contract reject the tokens.
4. Wait for any relayer to call `fin_transfer` with the original proof (also incentivized).

The attack is repeatable with any non-empty-`msg` fast transfer to a deployed token.

## Recommendation

Move `burn_tokens_if_needed` inside the **success branch only** (when `is_refund_required` is `false`). When a refund is required, tokens must be returned to the relayer intact — no burn should occur:

```rust
pub fn resolve_fast_transfer(
    &mut self,
    token_id: &AccountId,
    fast_transfer_id: &FastTransferId,
    amount: U128,
    is_ft_transfer_call: bool,
) -> U128 {
    if Self::is_refund_required(is_ft_transfer_call) {
        // Transfer failed: return tokens to relayer, do NOT burn
        self.remove_fast_transfer(fast_transfer_id);
        amount
    } else {
        // Transfer succeeded: burn to prevent double-minting on fin_transfer
        self.burn_tokens_if_needed(token_id.clone(), amount);
        U128(0)
    }
}
```

Additionally, consider preserving the fast-transfer record (marking it as failed rather than removing it) when the transfer fails, so that a subsequent `fin_transfer` call can detect the failed attempt and route tokens to the relayer rather than minting fresh tokens for the original recipient.

## Proof of Concept

1. Attacker deploys `attacker.near` whose `ft_on_transfer` always returns the full `amount` (rejecting all tokens).
2. Attacker calls `init_transfer` on the EVM bridge, locking 1000 USDC (a deployed token on NEAR), recipient = `attacker.near`, fee = 1 USDC, `msg` = `"some_dex_call"` (non-empty).
3. A trusted relayer calls `ft_transfer_call(bridge, 1000, FastFinTransferMsg{recipient: attacker.near, msg: "some_dex_call", ...})`.
4. Bridge's `ft_on_transfer` → `fast_fin_transfer_to_near_callback`:
   - Records fast transfer (relayer = `relayer.near`).
   - Calls `ft_transfer_call(attacker.near, 999, "some_dex_call")`.
5. `attacker.near.ft_on_transfer` returns `999` (reject). Token contract refunds 999 to bridge. Bridge holds 1000.
6. `resolve_fast_transfer` executes:
   - Schedules detached `burn(999)`.
   - `is_refund_required` → `true` (ft_transfer_call returned 0 used).
   - `remove_fast_transfer` erases record.
   - Returns `999`.
7. Token contract refunds 999 from bridge → relayer. Bridge holds 1.
8. Detached burn tries to burn 999 from bridge (holds 1) → fails silently.
9. Relayer calls `fin_transfer` with original EVM proof.
10. `process_fin_transfer_to_near`: `get_fast_transfer_status` → `None` → mints 999 USDC for `attacker.near`, mints 1 USDC fee for relayer.
11. **Result:** Relayer holds 999 USDC (refunded) + 1 USDC (fee) = 1000 USDC. `attacker.near` holds 999 USDC. Total NEAR-side supply: 1999 USDC vs. 1000 USDC locked on EVM. Net inflation: 999 USDC per cycle.

### Citations

**File:** near/omni-bridge/src/lib.rs (L888-891)
```rust
                    &fast_transfer.id(),
                    amount_without_fee,
                    !fast_transfer.msg.is_empty(),
                ),
```

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

**File:** near/omni-bridge/src/lib.rs (L1784-1804)
```rust
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
            match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
                Ok(value) => {
                    if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                        // Normal case: refund if the used token amount is zero
                        // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                        amount.0 == 0
                    } else {
                        // Unexpected case: don't refund
                        false
                    }
                }
                // Unexpected case: don't refund
                Err(_) => false,
            }
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
    }
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

**File:** near/omni-bridge/src/lib.rs (L1897-1902)
```rust
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
        };
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
