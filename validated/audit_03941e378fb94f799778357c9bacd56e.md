### Title
Fee Validation Without Decimal Normalization Check Causes Permanent Locking of User Funds - (File: near/omni-bridge/src/lib.rs)

### Summary

The `init_transfer` function validates that `fee < amount` in raw NEAR token units, but does not verify that `normalize_amount(amount - fee, decimals) > 0`. When a user's `amount_without_fee` is smaller than `10^(origin_decimals - dest_decimals)`, the normalized transfer amount rounds to zero via floor division. The `sign_transfer` function then panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and because the tokens were already locked/burned in the prior `init_transfer` call, they are permanently frozen with no recovery path.

### Finding Description

`init_transfer` (called via `ft_on_transfer`) locks or burns the user's tokens and stores the transfer message. The only fee guard at this stage is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

This check passes for any `fee = amount - 1`, leaving `amount_without_fee = 1`. Later, when a relayer calls `sign_transfer`, the bridge normalizes the net amount:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
``` [2](#0-1) 

`normalize_amount` uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [3](#0-2) 

For a token with `origin_decimals = 24` (NEAR) and `dest_decimals = 6`, the divisor is `10^18`. Any `amount_without_fee < 10^18` yoctoNEAR normalizes to 0, causing `sign_transfer` to panic. The tokens locked in `init_transfer_internal` are never returned because the panic occurs in a separate, later transaction. [4](#0-3) 

There is no `cancel_transfer` function, and `update_transfer_fee` only allows increasing the fee (not decreasing it), so there is no recovery path for the stuck transfer. [5](#0-4) 

### Impact Explanation

User funds are permanently frozen in the bridge contract. The maximum amount at risk per transfer is `10^(origin_decimals - dest_decimals) - 1` raw token units. For a 24→6 decimal pair (e.g., NEAR-native token bridging to a 6-decimal EVM token), this is up to `10^18 - 1` yoctoNEAR ≈ 1 NEAR per affected transfer. This matches the "permanent freezing of bridged funds" impact category.

### Likelihood Explanation

Any unprivileged user can trigger this by calling `ft_on_transfer` with an `amount` and `fee` such that `amount - fee < 10^(origin_decimals - dest_decimals)`. This can happen accidentally (user sets a fee very close to the transfer amount) or deliberately (self-griefing). The condition is reachable on any token pair where `origin_decimals > dest_decimals`, which is the normal operating mode documented in the codebase. [6](#0-5) 

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before locking tokens. Retrieve the destination token's `Decimals` and assert that `normalize_amount(amount_without_fee, decimals) > 0`. This mirrors the guard already present in `sign_transfer` but must be enforced at the point where tokens are committed, not at the point where signing is attempted.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `dest_decimals = 6` (divisor = `10^18`).
2. User calls `ft_on_transfer` transferring `amount = 5 * 10^17` yoctoNEAR (0.5 NEAR) with `fee = 0`.
3. `fee < amount` passes (0 < 5×10^17). Tokens are locked. Transfer message is stored.
4. Relayer calls `sign_transfer`.
5. `normalize_amount(5 * 10^17, {24, 6}) = 5 * 10^17 / 10^18 = 0`.
6. `require!(0 > 0)` panics → `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. The 0.5 NEAR is permanently locked in the bridge with no recovery mechanism. [2](#0-1) [1](#0-0)

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );
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
