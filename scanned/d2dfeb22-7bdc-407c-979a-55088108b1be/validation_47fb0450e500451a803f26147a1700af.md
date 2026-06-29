### Title
Permanently Locked Funds Due to `normalize_amount` Returning Zero in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR bridge contract accepts outbound transfer initiations (`init_transfer`) with amounts that pass the `fee < amount` check at creation time, but permanently locks user funds when `sign_transfer` later computes a normalized amount of zero via floor division, causing an irrecoverable panic.

### Finding Description

When a user initiates a NEAR→EVM transfer, `init_transfer` stores the transfer message after only checking `fee < amount`: [1](#0-0) 

The user's tokens are immediately locked in the bridge. Later, when a relayer calls `sign_transfer`, the amount is normalized for the destination chain's decimal representation: [2](#0-1) 

The `normalize_amount` function performs **floor division**: [3](#0-2) 

If `amount_without_fee()` is less than `10^(origin_decimals - decimals)`, the result is `0`. The subsequent `require!(amount_to_transfer > 0)` check then panics, and `sign_transfer` will **always** fail for this transfer. Since `sign_transfer` is the only path to finalize a NEAR→EVM transfer (via MPC signing), the funds are permanently locked with no cancel or refund mechanism.

**Concrete scenario:**
- Token registered with `origin_decimals = 24` (e.g., NEAR native token) and `decimals = 18` (EVM representation), giving a normalization factor of `10^6 = 1,000,000`.
- User calls `ft_on_transfer` with `amount = 500,000` and `fee = 0`.
- `fee < amount` check passes (0 < 500,000). Tokens are locked.
- `normalize_amount(500_000, decimals) = 500_000 / 1_000_000 = 0` (floor division).
- Every subsequent `sign_transfer` call panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
- The 500,000 units are permanently frozen in the bridge.

The protocol's own comment acknowledges dust locking when `fee = 0`, but does not address the case where the **entire** transfer amount normalizes to zero: [4](#0-3) 

### Impact Explanation

User funds are permanently frozen in the NEAR bridge contract. The transfer can never be signed, never finalized on the EVM side, and there is no `cancel_transfer` or refund path reachable by the user. This constitutes permanent loss/freezing of bridged funds, matching the Critical impact scope.

### Likelihood Explanation

Any unprivileged user who calls `ft_on_transfer` with a token amount smaller than the decimal normalization factor triggers this condition. For tokens with large decimal differences (e.g., 24 NEAR decimals → 18 EVM decimals, factor = 1,000,000), amounts below 1,000,000 base units are affected. This is reachable without any special privileges and requires no external dependency failure — only a small transfer amount.

### Recommendation

Add a minimum-amount check at `init_transfer` time that validates `normalize_amount(amount_without_fee(), decimals) > 0` before accepting the transfer and locking tokens. This mirrors the fix suggested in M-9: enforce the downstream constraint at the entry point so funds are never locked in an unrecoverable state.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = 10^6).
2. Call `ft_on_transfer` on the NEAR bridge with `amount = 500_000`, `fee = 0`, recipient on EVM.
3. Observe `init_transfer` succeeds — tokens are locked.
4. Have a trusted relayer call `sign_transfer` for this `transfer_id`.
5. Observe panic: `ERR_INVALID_AMOUNT_TO_TRANSFER` at `near/omni-bridge/src/lib.rs` line 482–485.
6. Repeat step 4 indefinitely — the result is always the same panic.
7. Confirm no `cancel_transfer` or refund path exists for the user to recover the locked tokens. [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L447-485)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

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
