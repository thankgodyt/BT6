### Title
Tokens Permanently Locked/Burned When Transfer Amount Normalizes to Zero - (`near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates a NEAR → foreign-chain transfer with an amount that, after fee deduction and decimal normalization, rounds down to zero, the tokens are irreversibly locked or burned in `init_transfer_internal` with no user-accessible recovery path. The `sign_transfer` function then panics on the `amount_to_transfer > 0` guard, leaving the transfer message stranded in `pending_transfers` forever.

### Finding Description

The NEAR bridge contract applies `normalize_amount` in `sign_transfer` to convert the NEAR-side token amount (e.g., 24 decimals) to the destination-chain precision (e.g., 18 decimals on EVM). The normalization uses integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

For a NEAR token with 24 `origin_decimals` bridged to an EVM token with 18 `decimals`, the divisor is `10^6`. Any `amount_without_fee` strictly less than `1_000_000` normalizes to `0`.

`sign_transfer` then enforces:

```rust
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

However, `init_transfer` only validates `fee.fee < amount`; it does **not** pre-check whether `normalize_amount(amount - fee, decimals) > 0`: [3](#0-2) 

`init_transfer_internal` unconditionally burns (for deployed tokens) or locks (for native tokens) the full amount before any normalization check occurs: [4](#0-3) 

The only code paths that remove a transfer message are `sign_transfer_callback` (only reached after a successful MPC signature) and `claim_fee_callback`. Neither is reachable when `sign_transfer` panics before calling the MPC signer. There is no public cancel or user-initiated refund function.

The protocol's own comment acknowledges the dust-locking behavior but only for sub-unit remainders, not for the case where the entire transferred amount normalizes to zero: [5](#0-4) 

### Impact Explanation

Any user who initiates a NEAR → EVM (or other lower-precision chain) transfer with an `amount - fee` below the normalization threshold loses those tokens permanently. For a 24→18 decimal bridge, the threshold is `10^6` base units. Burned bridge tokens are gone; locked native tokens are stranded in the contract with no user-accessible unlock path. This constitutes **permanent freezing of bridged funds**.

### Likelihood Explanation

The scenario is reachable by any unprivileged user calling `ft_transfer_call` on a NEP-141 token with a small amount. It is especially likely for:
- Users who have already transferred most of their balance and hold a small remainder (the direct analog to the external report's scenario).
- Tokens with large decimal differences (24 NEAR vs 18 EVM is the standard case).
- Users who set a non-zero fee that pushes `amount_without_fee` below the threshold.

No special permissions or admin compromise are required.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before locking/burning tokens. Retrieve the destination token's `Decimals` at initiation time and assert:

```rust
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the guard already present in `sign_transfer` but applies it before funds are committed, allowing the NEP-141 callback to refund the user instead of locking their tokens.

### Proof of Concept

1. A NEAR token is registered with `origin_decimals = 24`, `decimals = 18` (standard NEAR-to-EVM mapping). The normalization divisor is `10^6`.
2. User Alice calls `ft_transfer_call` sending `500_000` base units (< `10^6`) with `fee = 0` and an EVM recipient.
3. `init_transfer` accepts the call (`fee=0 < amount=500_000`). `init_transfer_internal` burns the 500_000 units and stores the transfer message.
4. A trusted relayer calls `sign_transfer` for Alice's transfer. `normalize_amount(500_000, {24, 18}) = 0`. The `require!(amount_to_transfer > 0)` guard panics. The relayer's transaction reverts.
5. The transfer message remains in `pending_transfers`. Alice's 500_000 base units are permanently burned. No recovery path exists. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

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
