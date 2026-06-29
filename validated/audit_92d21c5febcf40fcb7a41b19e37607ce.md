Audit Report

## Title
Decimal Normalization Truncation to Zero Permanently Freezes User Funds in NEAR→EVM Transfers - (File: near/omni-bridge/src/lib.rs)

## Summary

`normalize_amount` uses integer floor division, so any `amount_without_fee` smaller than `10^(origin_decimals - decimals)` normalizes to exactly `0`. `init_transfer_internal` burns or locks the full token amount in the same transaction that stores the transfer message, but the subsequent `sign_transfer` call always panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` when the normalized amount is `0`. No cancel or refund path exists for stored init transfers, so the user's tokens are permanently frozen.

## Finding Description

`normalize_amount` performs integer floor division with no lower-bound guard:

```rust
// near/omni-bridge/src/lib.rs L2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

The code comment at L2781–2782 acknowledges that "dust stays locked/burned" when `fee = 0`, but this only addresses the remainder after normalization — it does not address the case where the *entire* amount normalizes to `0`.

`init_transfer` validates only that `fee < amount`:

```rust
// near/omni-bridge/src/lib.rs L554-557
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

It does not check that `normalize_amount(amount - fee, decimals) > 0`. When storage balance is sufficient, execution proceeds directly to `init_transfer_internal`, which burns (deployed tokens) or locks (native tokens) the full amount and returns `U128(0)` — meaning no refund to the caller:

```rust
// near/omni-bridge/src/lib.rs L1850-1864
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
} else { ... }
...
U128(0)
```

Later, when a relayer calls `sign_transfer`, it recomputes the normalized amount and panics unconditionally for this transfer:

```rust
// near/omni-bridge/src/lib.rs L475-485
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

Because the burn/lock occurred in a prior, already-committed transaction, the revert of `sign_transfer` does not restore the tokens. The transfer message remains in storage but can never be signed. There is no cancel or refund function for stored init transfers.

## Impact Explanation

User tokens are burned (for deployed bridge tokens) or locked (for native tokens) and can never be recovered. This is a concrete instance of **permanent freezing of bridged funds**, which is an explicitly listed Critical impact in the allowed scope. The loss is irreversible: the transfer message persists in storage, `sign_transfer` will always revert for it, and no on-chain recovery path exists.

## Likelihood Explanation

Any unprivileged user who calls `ft_transfer_call` with an amount below the normalization threshold triggers this. For a token with `origin_decimals = 18` (EVM) and `decimals = 6` (NEAR), the threshold is `10^12` base units. Any transfer of fewer than `10^12` base units — e.g., less than 1 USDC-equivalent for a 6-decimal token — is affected. Users unfamiliar with the normalization factor can trigger this accidentally. The only on-chain guard (`fee < amount`) does not prevent it. The condition is repeatable and requires no special privileges.

## Recommendation

Add a normalization check inside `init_transfer` (or at the start of `init_transfer_internal`) **before** burning or locking tokens:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(addr) = token_address {
    if let Some(decimals) = self.token_decimals.get(&addr) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().unwrap_or(0),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This check must execute before `burn_tokens_if_needed` / `lock_tokens_if_needed` so that a failing check causes the entire `ft_transfer_call` to revert and refund the tokens to the sender.

## Proof of Concept

1. Register a token with `origin_decimals = 18`, `decimals = 6` (diff = 12, factor = `10^12`).
2. User calls `ft_transfer_call` sending `amount = 500_000_000_000` (5 × 10^11) with `fee = 0`.
3. `init_transfer` passes the only guard: `0 < 500_000_000_000`. ✓
4. Storage balance is sufficient → `init_transfer_internal` is called.
5. `burn_tokens_if_needed` burns 500,000,000,000 base units; `U128(0)` is returned (no refund).
6. Relayer calls `sign_transfer` for this transfer ID.
7. `normalize_amount(500_000_000_000, {origin_decimals:18, decimals:6})` = `500_000_000_000 / 10^12` = `0`.
8. `require!(0 > 0, ...)` panics → transaction reverts.
9. Tokens remain burned. Transfer message remains in storage. No recovery path exists.
10. User's funds are permanently frozen.

A local integration test can reproduce this by: (a) deploying the bridge contract with a mock token registered at the above decimals, (b) calling `ft_transfer_call` with the sub-threshold amount, (c) asserting the token balance decreased, (d) calling `sign_transfer` and asserting it panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and (e) asserting no refund was issued and the transfer message remains in storage. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
