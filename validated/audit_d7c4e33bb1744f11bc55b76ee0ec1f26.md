Audit Report

## Title
Missing Minimum Transfer Amount Allows Permanent Locking of Bridged Funds via Zero Normalized Amount - (`near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer_internal` burns or locks source-chain tokens before any decimal-normalization check is performed. When a user initiates a transfer with an amount smaller than the normalization factor (`10^(origin_decimals − decimals)`), `sign_transfer` always panics with `InvalidAmountToTransfer` because `normalize_amount` returns 0. No cancel or refund path exists for stuck `pending_transfers` entries, so the user's tokens are permanently lost.

## Finding Description

**Root cause:** `normalize_amount` performs integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

Any `amount < 10^(origin_decimals − decimals)` produces 0.

**Commit path (NEAR-origin tokens):**

1. User calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer` → `init_transfer_internal`.
2. `init_transfer_internal` burns or locks the full token amount unconditionally before returning: [2](#0-1) 
3. The transfer message is stored in `pending_transfers`. The only validation at initiation time is `fee < amount`: [3](#0-2) 
   No floor on `amount` itself is enforced.
4. A relayer later calls `sign_transfer`, which computes `normalize_amount` and panics: [4](#0-3) 
5. The transfer remains in `pending_transfers` indefinitely. `remove_transfer_message_without_refund` exists but is never called on this path; `remove_transfer_message` refunds storage but not the bridged tokens. No `cancel_transfer` function exists.

**Commit path (EVM-origin → non-NEAR destination):**

1. EVM `initTransfer` burns/locks tokens; only `fee >= amount` is rejected: [5](#0-4) 
2. NEAR `fin_transfer_callback` receives the proof, denormalizes the amount, and stores the `TransferMessage` in `pending_transfers` via `process_fin_transfer_to_other_chain`.
3. `sign_transfer` panics identically as above; EVM tokens are already gone.

**Why existing checks are insufficient:** The `fee < amount` guard at initiation time does not prevent `amount - fee` from being below the normalization factor. The `normalize_amount` docstring acknowledges dust truncation but only addresses the remainder case ("dust stays locked/burned when fee = 0"); it does not guard against the entire normalized amount being zero. [6](#0-5) 

The CLAUDE.md "Decimal Arithmetic Underflow (NOT a vulnerability)" note refers to the case where `origin_decimals < decimals` (subtraction underflow), not to the zero-normalized-amount case described here. [7](#0-6) 

## Impact Explanation

Permanent, irreversible loss of bridged funds. Tokens are burned or locked on the source chain with no recovery path. This matches the allowed critical impact: **permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, or Wormhole-routed flows**, and **decimal/normalization abuse that changes user balances**.

## Likelihood Explanation

Triggerable by any unprivileged token holder through the public `ft_transfer_call` / `initTransfer` entry points. Tokens bridged between chains with different decimal precisions (e.g., 18-decimal ERC-20 on Ethereum to 8-decimal representation on Solana/Bitcoin) are the common case. A user sending any amount below `10^(origin_decimals − decimals)` base units — including accidental dust amounts or a deliberate 1-wei call — triggers permanent loss. No special role, leaked key, or admin action is required.

## Recommendation

1. **Eager normalization check in `init_transfer`:** Before burning/locking, compute `normalize_amount(amount - fee, decimals)` and revert if the result is 0. This prevents the transfer from being accepted when it cannot be completed.
2. **Protocol-level minimum amount:** Enforce `amount - fee >= 10^(origin_decimals − decimals)` in each chain's `initTransfer` entry point for every registered token pair.
3. **User-callable `cancel_transfer`:** Add a timeout-based cancellation function that refunds locked/burned tokens for transfers that have been pending beyond a configurable threshold, as a safety net for any future stuck transfers.

## Proof of Concept

1. Register a token with `origin_decimals = 18`, `decimals = 8` (normalization factor = `10^10`).
2. Call `ft_transfer_call` on NEAR (or `OmniBridge.initTransfer` on EVM) with `amount = 1`, `fee = 0`. The call succeeds; 1 unit is burned/locked; the `TransferMessage` is stored in `pending_transfers`.
3. Call `sign_transfer(transfer_id, None, &None)` as a relayer.
4. Inside `sign_transfer`: `normalize_amount(1 - 0, {decimals: 8, origin_decimals: 18})` = `1 / 10^10` = `0`. The `require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer)` panics.
5. The transfer remains in `pending_transfers` forever. The 1 unit is permanently lost. No refund is possible.

Minimal unit test to confirm:
```rust
#[test]
fn test_dust_amount_normalizes_to_zero() {
    assert_eq!(
        Contract::normalize_amount(1, Decimals { decimals: 8, origin_decimals: 18 }),
        0
    );
}
``` [8](#0-7)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L380-384)
```text
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```

**File:** near/omni-bridge/src/tests/lib_test.rs (L1092-1125)
```rust
fn test_normalize_amount() {
    assert_eq!(
        Contract::normalize_amount(
            u128::MAX,
            Decimals {
                decimals: 18,
                origin_decimals: 18
            }
        ),
        u128::MAX
    );

    assert_eq!(
        Contract::normalize_amount(
            u128::MAX,
            Decimals {
                decimals: 18,
                origin_decimals: 24
            }
        ),
        u128::MAX / 1_000_000
    );

    assert_eq!(
        Contract::normalize_amount(
            u128::MAX,
            Decimals {
                decimals: 9,
                origin_decimals: 24
            }
        ),
        u128::MAX / 1_000_000_000_000_000
    );
}
```
