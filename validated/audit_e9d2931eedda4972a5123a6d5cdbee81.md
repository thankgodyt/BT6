Audit Report

## Title
Decimal Normalization Truncation to Zero Permanently Freezes Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` accepts and locks user tokens without verifying that the post-normalization transfer amount is non-zero. When a small ("dust") amount is sent whose net value is less than `10^(origin_decimals - decimals)`, `normalize_amount` floors it to zero via integer division. `sign_transfer` then unconditionally panics on the `require!(amount_to_transfer > 0, ...)` guard, and no cancel or refund path exists, leaving the tokens permanently frozen in the bridge contract.

## Finding Description

`normalize_amount` performs floor division: [1](#0-0) 

`init_transfer` (reached via `ft_transfer_call`) validates only that `fee < amount`: [2](#0-1) 

There is no check that `normalize_amount(amount - fee) > 0`. On success, `init_transfer_internal` locks the tokens and returns `U128(0)`, which the NEP-141 `ft_transfer_call` protocol interprets as "keep all tokens — no refund": [3](#0-2) 

When a relayer later calls `sign_transfer`, it computes the normalized amount and enforces: [4](#0-3) 

This `require!` panics, reverting the entire `sign_transfer` call. Because the panic occurs before the MPC signing promise is dispatched, `sign_transfer_callback` is never invoked, so the transfer message is never removed from `pending_transfers`: [5](#0-4) 

A search of the contract confirms there is no `cancel_transfer` or `refund_transfer` function. The transfer message remains in storage indefinitely with no recovery path.

## Impact Explanation

This is a **permanent freezing of bridged funds** — a Critical impact under the allowed scope. Any user who sends a sub-unit amount (one that normalizes to zero) loses their tokens irrecoverably. The tokens are locked/burned in `init_transfer_internal`, the transfer can never be signed, and no refund mechanism exists.

## Likelihood Explanation

Reachable by any unprivileged user via the public `ft_transfer_call` entry point. No special role or privilege is required. The condition is triggered for any token registered with `origin_decimals > decimals` (e.g., 24 NEAR-side decimals bridging to an 18-decimal EVM chain, a 6-decimal difference). Any transfer of fewer than `10^6` base units — a common "dust" or small-amount pattern — triggers the freeze. The code comment on `normalize_amount` itself acknowledges the floor-division behavior: [6](#0-5) 

## Recommendation

Add a normalization guard inside `init_transfer` (before `init_transfer_internal` is called) that mirrors the existing guard in `sign_transfer`. Resolve the token address and decimals for the destination chain, compute `normalize_amount(amount - fee, decimals)`, and `require!` the result is greater than zero. This prevents the irrecoverable locked-funds state at the point of token acceptance rather than at signing time.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (factor of `10^6`).
2. Alice calls `ft_transfer_call` with `amount = 500_000` and `fee = 0`. The `fee < amount` check passes.
3. `init_transfer_internal` locks 500,000 units and returns `U128(0)` — Alice's tokens are taken with no refund.
4. A relayer calls `sign_transfer` for Alice's transfer ID.
5. `normalize_amount(500_000, {origin: 24, dest: 18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics — transaction reverts, transfer message remains in storage.
7. Steps 4–6 repeat indefinitely. Alice's 500,000 units are permanently frozen with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1865)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
