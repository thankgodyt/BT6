Audit Report

## Title
Permanent Fund Loss via Decimal Normalization Dust When `fee = 0` — (`near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer_internal` locks or burns the full user-supplied `amount` before any normalization check is applied. When a token has fewer decimals on the destination chain than on NEAR, `normalize_amount` uses floor division, truncating any sub-unit remainder ("dust") to zero. If `fee = 0` and `amount` is smaller than the normalization factor (or not a multiple of it), `sign_transfer` panics with `InvalidAmountToTransfer` after funds are already gone, and no user-callable cancel or refund path exists to recover them.

## Finding Description

`init_transfer` (called via `ft_on_transfer`) validates only that `fee < amount`: [1](#0-0) 

This does **not** verify that `normalize_amount(amount − fee) > 0`. Control then passes to `init_transfer_internal`, which immediately locks or burns the full `transfer_message.amount`: [2](#0-1) 

Only later, when a trusted relayer calls `sign_transfer`, is the normalization check applied: [3](#0-2) 

`normalize_amount` uses floor division: [4](#0-3) 

The code comment explicitly acknowledges the dust-loss design but defers to `SECURITY.md`, which contains only a generic bug-bounty exclusion list with no mention of this behavior: [5](#0-4) [6](#0-5) 

When `sign_transfer` panics, the transfer message remains in storage but the tokens are already locked/burned. A search for any public `cancel`, `refund`, or `revert` function returns no results — `remove_transfer_message_without_refund` (used internally on storage failures) explicitly does not refund tokens, and no user-callable equivalent exists. [7](#0-6) 

## Impact Explanation

This is a concrete, permanent loss of user funds matching the allowed impact class: **decimal/normalization abuse that changes user balances** and **permanent freezing of bridged funds**. For native NEAR tokens, the `amount` is locked in the bridge escrow forever. For deployed (bridgeable) tokens, the `amount` is burned. No relayer can complete the transfer (normalized amount = 0 causes a panic), and no user-callable path exists to cancel or reclaim the funds.

## Likelihood Explanation

Any unprivileged user calling `ft_transfer_call` with `fee = 0` and an `amount` that is either smaller than the normalization factor or not a multiple of it triggers the bug. No special role or privilege is required. The condition is realistic for any token registered with `origin_decimals > decimals` (e.g., NEAR 24 → EVM 18, factor = 10⁶; NEAR 24 → EVM 6, factor = 10¹⁸). A user transferring a small or oddly-sized amount — a common pattern — can unknowingly trigger permanent loss.

## Recommendation

Add a pre-lock normalization check in `init_transfer` (or `init_transfer_internal`) before funds are locked or burned, mirroring the guard already present in `sign_transfer`:

```rust
let token_address = self.get_token_address(destination_chain, token_id.clone())
    .near_expect(BridgeError::TokenNotFound);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals,
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This ensures the transfer is rejected before any tokens are locked or burned, returning the full amount to the caller via the `ft_on_transfer` return value.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = 10⁶).
2. User calls `ft_transfer_call` on the token contract, transferring `amount = 500_000` (< 10⁶) with `fee = 0` and a valid EVM recipient.
3. `init_transfer` passes the `fee < amount` check (0 < 500_000).
4. `init_transfer_internal` locks 500_000 units in the bridge escrow (or burns them if it is a deployed token).
5. A trusted relayer calls `sign_transfer`. `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`. The `require!(amount_to_transfer > 0)` guard panics with `InvalidAmountToTransfer`.
6. The transfer message remains in storage; the 500_000 units remain locked/burned forever. The user has no recourse — no public cancel, refund, or revert function exists in the contract. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L1846-1847)
```rust
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
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

**File:** SECURITY.md (L1-26)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.
```
