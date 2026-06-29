Audit Report

## Title
Small-Amount Transfer Permanently Freezes Locked Tokens Due to Zero-Amount Check in `sign_transfer` - (File: near/omni-bridge/src/lib.rs)

## Summary
When a user initiates an outbound transfer with an amount that normalizes to zero on the destination chain's decimal scale, tokens are locked in `init_transfer_internal` before any normalization check occurs. The subsequent `sign_transfer` call then permanently panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and no user-callable recovery path exists to reclaim the locked funds.

## Finding Description
The outbound transfer flow is split across two phases with the critical check placed in the wrong phase.

**Phase 1 — `init_transfer_internal` (tokens locked, no normalization check):**
The only validation before locking is `fee < amount`. [1](#0-0) 
After that check passes, `burn_tokens_if_needed` and `lock_tokens_if_needed` execute unconditionally for NEAR-native tokens, with no check that the amount will survive normalization. [2](#0-1) 

**Phase 2 — `sign_transfer` (normalization check, too late):**
`normalize_amount` performs integer floor division; if `amount_without_fee < 10^(origin_decimals − decimals)`, the result is 0 and the function panics. [3](#0-2) 

The normalization itself: [4](#0-3) 

`sign_transfer` makes no state changes before the panic, so the transfer remains in `pending_transfers` with tokens locked. The function is `#[trusted_relayer]`-gated, so the user cannot call it themselves, and every relayer attempt will panic identically. [5](#0-4) 

**No recovery path exists:** A search of the contract confirms there is no `cancel_transfer`, `refund`, `withdraw`, `unlock`, or `recover` public function callable by the original sender. The only internal removal helper is `remove_transfer_message_without_refund`, which is called only in the storage-balance-insufficient path of `init_transfer_internal` — a path that is never reached for this scenario because storage is sufficient. [6](#0-5) 

## Impact Explanation
This is a concrete instance of **permanent freezing of bridged funds** — one of the explicitly listed Critical impact classes. Tokens are locked on-chain with no mechanism for the user or any non-privileged party to recover them. The funds are irrecoverably frozen in the bridge contract.

## Likelihood Explanation
Any unprivileged user who calls `ft_transfer_call` with an amount below the decimal-gap threshold triggers this. The threshold scales with the decimal gap: for a 24-decimal NEAR token bridged to a 6-decimal EVM token, the threshold is `10^18` base units — a non-trivial amount that a real user could easily send. The `init_transfer` path imposes no minimum-amount guard beyond `fee < amount`, so the triggering condition is reachable through a normal, public smart-contract call flow with no special privileges required. [1](#0-0) 

## Recommendation
Move the `normalize_amount > 0` check into `init_transfer_internal`, **before** `burn_tokens_if_needed` / `lock_tokens_if_needed` are called. If the normalized amount is zero, call `remove_transfer_message_without_refund` and return `transfer_message.amount` (triggering the NEP-141 refund via `ft_transfer_call`), exactly as the contract already does for the storage-balance-insufficient case:

```rust
// In init_transfer_internal, before locking tokens:
let decimals = ...; // fetch decimals for destination token
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
if normalized == 0 {
    self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
    return transfer_message.amount; // NEP-141 refund
}
```

Alternatively, add a user-callable `cancel_transfer` with a timeout that unlocks/refunds tokens for transfers stuck in `pending_transfers`.

## Proof of Concept
1. Register token `T` with `origin_decimals = 24`, `decimals = 6` (diff = 18).
2. User calls `ft_transfer_call` on `T` with `amount = 10^17`, `fee = 0`, valid recipient on destination chain.
3. `init_transfer` passes the `fee < amount` check; `init_transfer_internal` stores the transfer and locks `10^17` units of `T`.
4. Relayer calls `sign_transfer` for the resulting `transfer_id`.
5. `normalize_amount(10^17, {origin_decimals:24, decimals:6}) = 10^17 / 10^18 = 0`.
6. `require!(0 > 0, ERR_INVALID_AMOUNT_TO_TRANSFER)` panics — no state changes occur.
7. Transfer remains in `pending_transfers`; `10^17` units of `T` remain locked forever.
8. Every subsequent relayer call to `sign_transfer` for this `transfer_id` panics identically; the user has no callable recovery function.

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-447)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
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

**File:** near/omni-bridge/src/lib.rs (L1838-1848)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
