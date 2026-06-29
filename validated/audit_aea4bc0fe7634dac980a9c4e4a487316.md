Audit Report

## Title
Decimal Normalization Dust Permanently Locked When Transfer Fee Is Zero - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`normalize_amount` applies floor integer division when converting token amounts from higher-decimal source chains to lower-decimal destination chains. The truncated remainder ("dust") is permanently locked or burned in the NEAR bridge contract whenever a user initiates a transfer with `fee = 0`. When `fee > 0`, `claim_fee_callback` absorbs the dust into the relayer fee via `amount - denormalize(normalize(amount))`; when `fee = 0`, the transfer message is deleted immediately after signing with no equivalent recovery path.

## Finding Description

**Root cause — floor division in `normalize_amount`:** [1](#0-0) 

`amount / 10^diff_decimals` silently discards `amount % 10^diff_decimals`.

**Full amount (including dust) is locked/burned in `init_transfer_internal`:** [2](#0-1) 

`transfer_message.amount` — the complete user-supplied amount — is passed to `burn_tokens_if_needed` / `lock_tokens_if_needed`.

**`sign_transfer` normalizes only `amount_without_fee()` and signs the truncated value:** [3](#0-2) 

`amount_without_fee()` returns `amount - fee.fee`; when `fee = 0` this equals the full locked amount. The normalized (truncated) value is what gets signed and sent to the destination chain. [4](#0-3) 

**When `fee = 0`, the transfer message is deleted immediately after signing — no dust recovery:** [5](#0-4) 

**When `fee > 0`, dust is recovered via `claim_fee_callback`:** [6](#0-5) 

`fee = transfer_message.amount.0 - denormalized_amount` captures both the user-specified fee and the normalization remainder. This path is entirely absent for zero-fee transfers because the transfer message no longer exists after `sign_transfer_callback` deletes it.

## Impact Explanation

This is a concrete, permanent loss of bridged user funds — directly matching the allowed impact class of "decimal/normalization abuse that changes user or protocol balances." For tokens with large decimal differences (e.g., 24 decimals on NEAR, 6 decimals on EVM, `diff_decimals = 18`), up to `10^18 - 1` yocto-units per transfer can be permanently locked in the bridge escrow or burned, with no recovery mechanism. The loss is irreversible: once `remove_transfer_message` is called and the transfer message is gone, neither the user nor any relayer can reclaim the dust.

## Likelihood Explanation

Any token holder can trigger this by calling `ft_transfer_call` with `fee = 0` and a non-round amount. No special role is required for the initiating step. The trusted relayer then calls `sign_transfer` as part of normal operation — the relayer has no reason to refuse, and the user's funds are already locked at that point. The condition fires on every transfer where `amount % 10^diff_decimals != 0` and `fee = 0`, making it repeatable and deterministic.

## Recommendation

1. **Round down before locking:** In `init_transfer_internal` (or before), compute `effective_amount = normalize_amount(amount_without_fee) * 10^diff_decimals` and return the dust (`amount - effective_amount - fee`) to the sender via a refund before locking/burning.
2. **Alternatively, reject non-round zero-fee transfers:** When `fee = 0` and `origin_decimals != decimals`, require `amount % 10^diff_decimals == 0`, panicking otherwise so the `ft_transfer_call` refunds the full amount.

## Proof of Concept

**Setup:** Token with `origin_decimals = 24` on NEAR, `decimals = 6` on EVM (`diff_decimals = 18`).

1. User calls `ft_transfer_call` with `amount = 1_999_999_999_999_999_999_000_000` and `fee = 0`.
2. `init_transfer_internal` locks the full `1_999_999_999_999_999_999_000_000` units.
3. Trusted relayer calls `sign_transfer`.
4. `normalize_amount(1_999_999_999_999_999_999_000_000, {origin:24, dest:6})` = `1_999_999_999_999_999_999_000_000 / 10^18` = `1_999_999` (passes `> 0` check).
5. MPC signs payload for `amount = 1_999_999` (6 decimals).
6. `sign_transfer_callback`: `fee.is_zero()` → `remove_transfer_message(transfer_id)`. Transfer message deleted.
7. EVM receives `1_999_999` units (6 decimals = 1.999999 tokens).
8. Dust = `1_999_999_999_999_999_999_000_000 - 1_999_999 * 10^18` = `999_000_000_000_000_000` yocto-units remains permanently locked in the NEAR bridge with no recovery path.

A local integration test can reproduce this by: deploying a mock token with 24 decimals, registering it with 6-decimal EVM decimals, calling `ft_transfer_call` with the above amount and `fee = 0`, simulating the MPC callback, and asserting that the bridge's locked balance exceeds `denormalize(normalize(amount))` with no callable function to recover the difference.

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-480)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1128-1133)
```rust
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-types/src/lib.rs (L593-595)
```rust
    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
```
