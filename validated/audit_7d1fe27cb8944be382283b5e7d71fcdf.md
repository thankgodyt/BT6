Based on my code review, the vulnerability claim is accurate. Here is my assessment:

**Code verification:**

- `init_transfer` only validates `fee < amount` [1](#0-0)  — no normalization check before burning/locking.
- `init_transfer_internal` burns/locks the full `amount` [2](#0-1)  before any normalization occurs.
- `sign_transfer` calls `normalize_amount` and panics via `require!` if the result is zero [3](#0-2) .
- `normalize_amount` uses floor division and can return 0 for dust amounts [4](#0-3) .
- No `cancel_transfer` or recovery function exists anywhere in the contract. [5](#0-4) 
- The code comment at line 2781–2783 acknowledges dust truncation but only addresses sub-unit remainders, not the case where the entire normalized amount is zero. [6](#0-5) 

---

Audit Report

## Title
Permanent Freezing of Bridged Funds via Zero Normalized Amount After Decimal Truncation — (File: near/omni-bridge/src/lib.rs)

## Summary
`init_transfer` accepts and immediately burns or locks user tokens for any transfer where `fee < amount`, without validating that the net amount after decimal normalization is non-zero. When `normalize_amount(amount - fee)` truncates to zero due to floor division across a decimal gap (e.g., NEAR 24-decimal token bridging to Ethereum 18-decimal), every subsequent call to `sign_transfer` permanently panics. The burned or locked tokens are unrecoverable because no cancel or recovery function exists.

## Finding Description
`init_transfer` constructs a `TransferMessage` and enforces only one amount constraint: `transfer_message.fee.fee < transfer_message.amount` (L554–557). It then calls `init_transfer_internal`, which stores the transfer in `pending_transfers` and immediately burns (for deployed tokens) or locks (for native tokens) the full `amount` (L1850–1857) — before any normalization is performed.

Later, when a relayer calls `sign_transfer`, it retrieves the stored transfer, fetches the destination token's `Decimals`, and computes:
```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()...,
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```
(L475–485). `normalize_amount` uses floor division: `amount / 10^(origin_decimals - decimals)` (L2784–2787). For a token with `origin_decimals = 24` and `decimals = 18`, the divisor is `10^6`. Any `amount_without_fee < 1_000_000` normalizes to zero, causing `require!` to panic unconditionally. The transfer remains in `pending_transfers` forever, and no `cancel_transfer` or equivalent recovery function exists anywhere in the contract.

## Impact Explanation
This is a concrete instance of **permanent freezing of bridged funds**. For burned deployed tokens, the supply is reduced with no corresponding mint on the destination chain. For locked native tokens, the locked balance is incremented and can never be decremented because `sign_transfer` always panics and `fin_transfer`/`claim_fee` require a valid on-chain finalization proof that can never be produced. This matches the allowed Critical impact class: permanent freezing of bridged funds across NEAR and EVM chains.

## Likelihood Explanation
Any unprivileged user who sends a "dust" amount of a token whose `origin_decimals` exceeds the destination chain's `decimals` triggers this. For the NEAR→Ethereum path (24 vs 18 decimals), any transfer with `amount_without_fee < 1,000,000 yocto-units` is affected. This is a realistic user error (e.g., sending 1 unit of a high-precision token), and the protocol silently accepts it at `init_transfer` time with no warning. The trigger is a standard `ft_transfer_call` — no special privileges required.

## Recommendation
Add a validation in `init_transfer` (after resolving the destination token's decimals but before calling `init_transfer_internal`) that the normalized net amount is non-zero:
```rust
require!(
    Self::normalize_amount(amount.0 - init_transfer_msg.fee.0, decimals) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```
Alternatively, add a `cancel_transfer` function that allows the original sender to reclaim tokens from a pending transfer whose normalized amount is zero.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (NEAR→Ethereum path).
2. User calls `ft_transfer_call` on the token contract with `amount = 500_000` and `msg` encoding `InitTransferMsg { fee: U128(0), ... }`.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000`); `init_transfer_internal` burns 500,000 units and stores the transfer.
4. Relayer calls `sign_transfer` with the resulting `transfer_id`.
5. `normalize_amount(500_000, {origin_decimals:24, decimals:18})` = `500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` panics. The call reverts.
7. Steps 4–6 repeat on every subsequent relayer attempt. The 500,000 units are permanently burned and the transfer is stuck in `pending_transfers` indefinitely with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1-10)
```rust
#![allow(clippy::too_many_arguments)]
use near_contract_standards::fungible_token::metadata::FungibleTokenMetadata;
use near_contract_standards::storage_management::StorageBalance;
use near_plugins::{
    access_control, access_control_any, pause, AccessControlRole, AccessControllable, Pausable,
    Upgradable,
};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, LookupSet, UnorderedMap};
```

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
