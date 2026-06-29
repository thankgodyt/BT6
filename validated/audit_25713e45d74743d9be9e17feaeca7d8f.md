Audit Report

## Title
Integer Division in `normalize_amount` Permanently Locks User Funds When Transfer Amount Is Below Decimal Precision Threshold — (File: near/omni-bridge/src/lib.rs)

## Summary

`normalize_amount` uses floor integer division to scale a token amount from origin-chain precision to destination-chain precision. When a user initiates a transfer with an amount smaller than `10^(origin_decimals - decimals)`, the normalized result is `0`. `sign_transfer` then panics with `InvalidAmountToTransfer`, but the user's tokens are already locked in the bridge with no recovery path, as no `cancel_transfer` function exists in the contract.

## Finding Description

`normalize_amount` at lines 2784–2787 performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

`sign_transfer` calls this and guards against a zero result at lines 475–485:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
``` [2](#0-1) 

However, `init_transfer` only validates `fee < amount` before accepting tokens and storing the transfer message:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

There is no check that `normalize_amount(amount - fee, decimals) > 0` at the point of entry. Once `init_transfer_internal` stores the transfer message and `ft_on_transfer` returns `0` (keeping the tokens), the funds are locked. [4](#0-3) 

Every subsequent call to `sign_transfer` for this transfer will always panic at the same guard. `sign_transfer_callback` only removes the transfer message when MPC signing **succeeds** and `fee.is_zero()`:

```rust
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
``` [5](#0-4) 

Since `sign_transfer` panics before the MPC call is ever made, this callback is never reached. A grep across the entire repository confirms there is no `cancel_transfer` function. The `update_transfer_fee` function can only **increase** the fee (`fee.fee >= current_fee.fee`), which makes `amount_without_fee()` smaller, keeping the normalized result at zero and making recovery impossible. [6](#0-5) 

## Impact Explanation

This constitutes **permanent freezing of bridged funds**, which is an explicitly listed Critical impact. Any user who initiates a NEAR → foreign-chain transfer with an amount below the minimum representable unit on the destination chain permanently loses their tokens. The tokens are locked in the bridge contract with no mechanism to recover them. The contract's own comment at lines 2781–2783 acknowledges the floor-division behavior but only addresses the "dust remainder" case, not the case where the entire amount normalizes to zero. [7](#0-6) 

## Likelihood Explanation

The condition is reachable by any unprivileged user who calls `ft_transfer_call` with a small amount. No special role or permission is required. For tokens with a large decimal difference between origin and destination chains (e.g., NEAR's 24-decimal tokens bridged to EVM chains that register them at 18 decimals), the minimum transferable unit is `10^6` base units. Any amount below this threshold triggers the permanent lock. This is a realistic user mistake, particularly for tokens with high decimal differences, and requires no attacker — a user can self-inflict this loss.

## Recommendation

Add a validation in `init_transfer` (before tokens are accepted) that `normalize_amount(amount - fee, decimals) > 0` for the destination chain. This check must be placed before `init_transfer_internal` stores the transfer message, so that `ft_on_transfer` returns the full amount to the sender on failure:

```rust
// In init_transfer, after building transfer_message and before init_transfer_internal:
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(transfer_message.amount.0 - transfer_message.fee.fee.0, decimals) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the guard already present in `sign_transfer` but enforces it at the entry point before funds are accepted. [8](#0-7) 

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (6-decimal difference, divisor = 1,000,000).
2. Call `ft_transfer_call` on the token contract with `amount = 500_000` and `msg` encoding an `InitTransferMsg` with `fee = 0` and a valid EVM recipient.
3. `init_transfer` accepts the tokens: `fee=0 < amount=500_000` passes the only guard. Transfer message stored in `pending_transfers`. `ft_on_transfer` returns `0` — tokens locked.
4. Trusted relayer calls `sign_transfer` for this `transfer_id`.
5. `normalize_amount(500_000, diff=6) = 500_000 / 1_000_000 = 0` → `require!(0 > 0, ...)` panics with `InvalidAmountToTransfer`.
6. No MPC call is made; `sign_transfer_callback` is never reached; transfer message stays in `pending_transfers`.
7. Repeat step 4 indefinitely — always panics. Tokens are permanently locked with no recovery path.
8. Attempting `update_transfer_fee` to increase the fee only reduces `amount_without_fee`, keeping the normalized result at zero.

### Citations

**File:** near/omni-bridge/src/lib.rs (L398-402)
```rust
                let current_fee = transfer.message.fee;
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

**File:** near/omni-bridge/src/lib.rs (L554-584)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );

        let required_storage_balance =
            self.required_balance_for_init_transfer_message(transfer_message.clone());

        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
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
