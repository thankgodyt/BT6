### Title
Decimal Normalization Dust Permanently Locked/Burned When `fee = 0` — (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` locks or burns the full user-supplied `amount` before `sign_transfer` applies `normalize_amount`. When the token has fewer decimals on the destination chain than on NEAR, any sub-unit remainder ("dust") is truncated to zero by floor division. If `fee = 0`, that dust is permanently locked in the bridge escrow (native tokens) or burned (deployed tokens) with no recovery path. The code comment explicitly acknowledges this: *"When fee = 0, dust stays locked/burned"*, but no guard prevents the transfer from being initiated in the first place, and no cancel/refund mechanism exists.

### Finding Description

`init_transfer` (called via `ft_on_transfer`) stores the transfer message and immediately locks or burns the full `amount` in `init_transfer_internal`: [1](#0-0) 

The only pre-lock validation on the amount is: [2](#0-1) 

This only requires `fee < amount`; it does **not** verify that `normalize_amount(amount − fee) > 0`.

Later, when a trusted relayer calls `sign_transfer`, the amount is normalized for the destination chain: [3](#0-2) 

`normalize_amount` uses floor division: [4](#0-3) 

If `amount − fee < normalization_factor` (e.g., `amount = 1`, `fee = 0`, and the token has 24 NEAR decimals vs 18 EVM decimals → factor = 10⁶), `normalize_amount` returns 0, and `sign_transfer` panics with `InvalidAmountToTransfer`. The transfer message remains in storage but the tokens are already gone. There is no user-callable cancel or refund function anywhere in the contract.

The code comment acknowledges the dust-loss design but references `SECURITY.md` for details: [5](#0-4) 

`SECURITY.md` contains only a generic bug-bounty exclusion list and says nothing about this behavior.

### Impact Explanation

A user who initiates a transfer with `fee = 0` and an `amount` smaller than the normalization factor (or with a non-zero sub-unit remainder) permanently loses those tokens. For native tokens they are locked in the bridge escrow forever; for deployed tokens they are burned. No relayer can complete the transfer (normalized amount = 0), and no user-callable path exists to cancel or reclaim the locked/burned funds. This is a direct, permanent loss of user funds — escrow mis-accounting / decimal-normalization abuse that changes user balances.

### Likelihood Explanation

Medium. The condition requires:
1. A token registered with `origin_decimals > decimals` (e.g., NEAR 24 → EVM 18, factor = 10⁶; or NEAR 24 → EVM 6, factor = 10¹⁸).
2. The user supplies `amount` (with `fee = 0`) that is not a multiple of the normalization factor, or is smaller than it.

Any unprivileged user calling `ft_transfer_call` with such an amount triggers the bug. No special role or privilege is required.

### Recommendation

Add a pre-lock check in `init_transfer` (or `init_transfer_internal`) that verifies the normalized net amount is greater than zero before locking or burning tokens:

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

This mirrors the check already present in `sign_transfer` but applies it **before** funds are locked/burned.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (normalization factor = 10⁶).
2. User calls `ft_transfer_call` on the token contract, transferring `amount = 500_000` (< 10⁶) with `fee = 0` and a valid EVM recipient.
3. `init_transfer` passes the `fee < amount` check (0 < 500_000). `init_transfer_internal` locks 500_000 units in the bridge escrow.
4. A trusted relayer calls `sign_transfer`. `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`. The `require!(amount_to_transfer > 0)` guard panics.
5. The transfer message remains in storage; the 500_000 units remain locked forever. The user has no recourse. [2](#0-1) [6](#0-5) [3](#0-2) [7](#0-6)

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
