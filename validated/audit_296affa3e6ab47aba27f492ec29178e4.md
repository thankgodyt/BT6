Audit Report

## Title
Permanently Locked Funds Due to `normalize_amount` Returning Zero in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` accepts and locks user tokens after only verifying `fee < amount`, with no check that the post-normalization transfer amount is nonzero. When `sign_transfer` later computes `normalize_amount(amount_without_fee(), decimals)` via floor division and the result is zero, it panics unconditionally. Because no cancel or refund path exists for the user, the locked tokens are permanently frozen in the bridge contract.

## Finding Description

**Root cause — missing pre-condition at entry point:**

`init_transfer` stores the transfer and locks tokens after a single guard: [1](#0-0) 

No check is made that `normalize_amount(amount - fee, decimals) > 0`.

**Normalization uses floor division:** [2](#0-1) 

For a token with `origin_decimals = 24` and `decimals = 18`, the divisor is `10^6`. Any `amount_without_fee()` below `1_000_000` produces `0`.

**`sign_transfer` panics irrecoverably:** [3](#0-2) 

This panic is deterministic — the stored transfer message never changes, so every future call to `sign_transfer` for the same `transfer_id` will panic identically.

**No user-accessible escape hatch:** A search of `lib.rs` finds no `cancel_transfer`, `refund_transfer`, or equivalent public function callable by the original depositor. The only refund path visible (`init_transfer_resume` returning `transfer_message.amount`) is gated on a storage-payment failure during the yield-resume flow, not on a failed `sign_transfer`. [4](#0-3) 

## Impact Explanation

This constitutes **permanent freezing of bridged funds** on the NEAR side. The tokens are transferred into the bridge contract via `ft_on_transfer`, the transfer record is stored, and no on-chain mechanism allows the user to retrieve them once `sign_transfer` is stuck in a permanent panic loop. This matches the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM."*

## Likelihood Explanation

Any unprivileged user can trigger this by calling `ft_on_transfer` with an amount smaller than the decimal normalization factor for the target chain. For the common NEAR→EVM case (`origin_decimals = 24`, `decimals = 18`, factor = `10^6`), any transfer of fewer than `1_000_000` yoctoNEAR-equivalent base units is affected. No special role, key, or external dependency is required — only a small transfer amount and a valid registered token.

## Recommendation

Add a normalization check inside `init_transfer` before storing the transfer message, mirroring the downstream constraint:

```rust
let decimals = self.get_token_decimals_for_destination(&token_id, &init_transfer_msg.recipient);
let normalized = Self::normalize_amount(
    (amount.0 - init_transfer_msg.fee.0),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This ensures tokens are never locked in a state where `sign_transfer` will always fail.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = `10^6`).
2. Call `ft_on_transfer` on the NEAR bridge with `amount = 500_000`, `fee = 0`, and a valid EVM recipient.
3. Confirm `init_transfer` succeeds — tokens are locked in the contract.
4. Have a trusted relayer call `sign_transfer` for the resulting `transfer_id`.
5. Observe panic at `ERR_INVALID_AMOUNT_TO_TRANSFER` (`lib.rs` L482–485): `normalize_amount(500_000, decimals) = 0`.
6. Repeat step 4 — result is always the same panic.
7. Confirm no public function allows the user to recover the locked `500_000` units. [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L631-643)
```rust
        if response.is_err() {
            env::log_str("Init transfer resume timeout");
        }

        if let Err(err) = self.try_to_transfer_balance_from_message_account(
            &message_storage_account_id,
            NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
            &storage_owner,
            self.required_balance_for_init_transfer_message(transfer_message.clone()),
        ) {
            env::log_str(&format!("Error paying native fee and storage: {err}"));
            return transfer_message.amount;
        }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
