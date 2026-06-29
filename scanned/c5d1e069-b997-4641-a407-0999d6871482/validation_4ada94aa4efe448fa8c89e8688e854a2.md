### Title
`init_transfer` Accepts Amounts That Permanently Freeze Funds Due to Decimal Normalization Rounding to Zero — (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts any transfer amount where `fee < amount`, but `sign_transfer` will always panic if `normalize_amount(amount_without_fee, decimals)` rounds down to zero via floor division. When a token has more decimals on NEAR than on the destination chain, any amount below the normalization divisor passes `init_transfer` but permanently bricks the transfer, freezing the user's tokens with no recovery path.

### Finding Description

The `init_transfer` function (called via `ft_on_transfer`) validates only that `fee.fee < amount`: [1](#0-0) 

It then locks or burns the user's tokens and stores the `TransferMessage`. Later, `sign_transfer` computes the destination-chain amount via `normalize_amount`, which uses floor division: [2](#0-1) 

`sign_transfer` then enforces: [3](#0-2) 

If `origin_decimals > decimals` (NEAR has more decimals than the destination chain), the divisor is `10^(origin_decimals - decimals)`. Any `amount_without_fee` smaller than this divisor normalizes to zero, causing `sign_transfer` to always panic with `BridgeError::InvalidAmountToTransfer`. The stored transfer message can never be completed, and there is no cancel/refund path visible in the contract.

### Impact Explanation

Tokens are permanently frozen. For a token with 24 decimals on NEAR bridging to a chain where it has 18 decimals (divisor = 10^6), any user who calls `init_transfer` with `amount_without_fee < 1,000,000` will have their tokens locked or burned on NEAR with no way to recover them. This matches the **Critical** impact category: permanent freezing of bridged funds.

### Likelihood Explanation

Any token registered with `origin_decimals > decimals` is affected. A user (or an attacker deliberately griefing another user) can trigger this by initiating a transfer with a small amount. The entry path is fully unprivileged: `ft_transfer_call` → `ft_on_transfer` → `init_transfer`. No special role or key is required.

### Recommendation

Add a minimum-amount guard inside `init_transfer` (or `init_transfer_internal`) that checks the normalized `amount_without_fee` is greater than zero before locking/burning tokens and storing the transfer message. Specifically, retrieve the token's `Decimals` at initiation time and assert:

```rust
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals,
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the check already present in `sign_transfer` and prevents the transfer from being accepted in the first place.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (divisor = 10^6).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes the `fee < amount` check, locks 500,000 tokens, stores the `TransferMessage`.
4. Relayer calls `sign_transfer`.
5. `normalize_amount(500_000, decimals) = 500_000 / 1_000_000 = 0`.
6. `require!(amount_to_transfer > 0, ...)` panics — every future call to `sign_transfer` for this transfer also panics.
7. The 500,000 tokens are permanently frozen with no recovery mechanism. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L471-485)
```rust
        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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

**File:** near/omni-bridge/src/lib.rs (L540-557)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
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
