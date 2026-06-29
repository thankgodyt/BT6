### Title
Zero-Normalized Amount Causes Permanent Transfer Lock — (`near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates an outbound transfer (NEAR → EVM) with an amount smaller than `10^(origin_decimals − decimals)`, the transfer is stored in `pending_transfers` and the user's tokens are locked/burned, but every subsequent call to `sign_transfer` will permanently revert with `InvalidAmountToTransfer`. There is no cancellation or refund path, so the funds are frozen forever.

### Finding Description

`normalize_amount` uses floor division to convert a NEAR-precision amount to the destination chain's precision: [1](#0-0) 

For a token registered with `origin_decimals = 24` and `decimals = 18` (a common NEAR-to-EVM pairing), any amount below `1_000_000` (1 µNEAR) normalises to `0`.

The zero-amount guard exists only inside `sign_transfer`, which is called **after** the transfer has already been committed to storage: [2](#0-1) 

The transfer is committed (and tokens consumed) inside `init_transfer_internal`, which is invoked from the `ft_on_transfer` callback when the user sends tokens to the bridge. That function has no pre-check that the post-normalization amount will be non-zero: [3](#0-2) 

Once stored, the only removal paths for a `pending_transfers` entry are `claim_fee_callback` (requires a proof of destination-chain finalization that will never exist) and `fin_transfer_callback` (same requirement). There is no user-callable cancel or refund function. The transfer is permanently stuck.

### Impact Explanation

User funds (NEP-141 tokens or native NEAR wrapped as wNEAR) are permanently frozen inside the bridge contract. The bridge's `ft_on_transfer` returns `0` (signalling full consumption), so the NEP-141 contract does not refund the sender. Every call to `sign_transfer` for that `transfer_id` reverts, and no other code path removes the entry. This constitutes permanent loss of bridged funds — matching the "permanent freezing of bridged funds" critical impact category.

### Likelihood Explanation

The condition is reachable by any unprivileged user who calls `ft_transfer_call` on a registered NEAR token with a small amount. For tokens with a 6-decimal gap (e.g., 24 NEAR decimals → 18 EVM decimals), amounts below `1_000_000` yocto-units trigger the bug. A user sending "dust" or making a rounding error can hit this silently — the `ft_on_transfer` call succeeds and returns no error to the sender.

### Recommendation

Add a normalization check inside `ft_on_transfer` (or at the top of `init_transfer_internal`) before the transfer is committed. If `normalize_amount(amount_without_fee, decimals) == 0`, return the full amount to the caller as a refund instead of storing the transfer:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the guard already present in `sign_transfer` but places it at the correct, earlier point in the lifecycle — analogous to the recommended fix in the reference report ("exit the function if the calculated amount is 0").

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (standard NEAR-to-EVM setup).
2. Call `ft_transfer_call` on that token, sending `500_000` yocto-units to the bridge with a valid `InitTransferMsg` (fee = 0).
3. `ft_on_transfer` succeeds; the transfer is stored in `pending_transfers`; the 500 000 units are consumed.
4. Call `sign_transfer` for the resulting `transfer_id`.
5. `normalize_amount(500_000, {origin: 24, decimals: 18})` = `500_000 / 1_000_000` = `0`.
6. `require!(amount_to_transfer > 0, …)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Repeat step 4 indefinitely — it always reverts. The 500 000 units are permanently locked. [1](#0-0) [2](#0-1) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
