Audit Report

## Title
Missing Pre-Transfer Normalization Check Permanently Freezes Bridged Funds - (`near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` locks user tokens after only verifying `fee < amount`, without checking that `normalize_amount(amount_without_fee())` is non-zero. When the post-fee amount is smaller than the decimal divisor between origin and destination chains, `sign_transfer` permanently panics with `InvalidAmountToTransfer`. No cancel or refund path exists, making the locked tokens irrecoverable.

## Finding Description
`normalize_amount` performs floor division to convert NEAR-side amounts to destination-chain representation: [1](#0-0) 

The code comment explicitly acknowledges that when `fee = 0`, dust stays locked/burned. However, the issue extends beyond dust: the entire `amount_without_fee()` can normalize to zero.

`init_transfer_internal` stores the transfer and locks tokens after only this check: [2](#0-1) 

No validation of `normalize_amount(amount_without_fee()) > 0` is performed at this stage. Later, when a relayer calls `sign_transfer`, the normalized amount is computed and enforced: [3](#0-2) 

`amount_without_fee()` is a simple subtraction: [4](#0-3) 

If `amount_without_fee()` is positive but less than `10^(origin_decimals - decimals)`, `normalize_amount` returns 0 and `sign_transfer` always panics. The only paths that call `remove_transfer_message` require either a finalization proof from the destination chain (via `claim_fee_callback`) or a successful token send (via `fin_transfer_send_tokens_callback`) — neither is reachable when `sign_transfer` is permanently blocked.

`update_transfer_fee` cannot rescue the transfer either, as it only allows the fee to be **increased**: [5](#0-4) 

Increasing the fee further reduces `amount_without_fee()`, making the situation worse, not better.

## Impact Explanation
Any tokens locked by `init_transfer` where `normalize_amount(amount_without_fee()) = 0` are permanently frozen in the bridge contract with no recovery mechanism. This is a concrete instance of **permanent freezing of bridged funds**, matching the Critical impact category. The decimal gap between NEAR (24 decimals) and EVM chains (18 decimals) is a standard production configuration, making the divisor 1,000,000 — any `amount_without_fee()` below this threshold is permanently lost.

## Likelihood Explanation
The condition is reachable by any unprivileged user calling `ft_transfer_call` with a small amount or a fee that leaves a sub-unit remainder. No special role or permission is required. The NEAR-to-EVM decimal gap (24 → 18, divisor = 1,000,000) is a real production configuration. Users may trigger this accidentally with low-value transfers or by setting a fee that reduces the transferable amount below the minimum unit threshold.

## Recommendation
In `init_transfer_internal`, after constructing the `TransferMessage`, look up the destination token's `Decimals` and compute `normalize_amount(amount_without_fee())`. If the result is zero, do not store the transfer message or lock tokens — instead return a non-zero value from `ft_on_transfer` to trigger the NEP-141 automatic refund to the sender.

As a complementary mitigation, implement a `cancel_transfer` function callable only by the original sender that removes the pending transfer message and refunds the locked tokens, which would also address other stuck-transfer scenarios.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = 1,000,000).
2. Call `ft_transfer_call` with `amount = 500_000`, `fee = 0`, and a valid Ethereum recipient.
3. `init_transfer` passes the `fee < amount` check (0 < 500,000) and locks 500,000 units. [2](#0-1) 
4. Relayer calls `sign_transfer` → `normalize_amount(500_000, {24, 18})` = 500,000 / 1,000,000 = 0 → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. [6](#0-5) 
5. No cancel path exists. `remove_transfer_message` is unreachable. Tokens remain permanently locked.
6. Variant: `amount = 1_500_000`, `fee = 1_000_000` → `amount_without_fee() = 500_000` → same outcome. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-401)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
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

**File:** near/omni-types/src/lib.rs (L593-595)
```rust
    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
```
