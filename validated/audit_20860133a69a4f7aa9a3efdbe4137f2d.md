Audit Report

## Title
Missing Normalization Check in `init_transfer` Permanently Locks Tokens When `sign_transfer` Enforces `amount_to_transfer > 0` - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` accepts any deposit satisfying `fee < amount` without verifying that the decimal-normalized net amount is nonzero. For tokens whose NEAR-side decimals exceed the destination-chain decimals (e.g., 24 → 18), any net amount below `10^(origin_decimals - decimals)` normalizes to zero via floor division. `sign_transfer` then unconditionally panics on the zero result, the transfer message is never removed from storage, and the locked or burned tokens have no recovery path.

## Finding Description

**Step 1 – `init_transfer` accepts the deposit without a normalization check.** [1](#0-0) 

Only `fee.fee < amount` is enforced. Token decimals are not consulted; no check is made that `normalize_amount(amount - fee, decimals) > 0`.

**Step 2 – `normalize_amount` uses floor division.** [2](#0-1) 

For `origin_decimals = 24`, `decimals = 18`, the divisor is `10^6`. Any net amount below `1_000_000` base units divides to zero. The inline comment explicitly acknowledges: *"When fee = 0, dust stays locked/burned."* This confirms the behavior is present in the code, though the comment addresses the dust-remainder case rather than the full-zero normalization case where the entire transfer is uncompletable.

**Step 3 – `sign_transfer` hard-blocks on the zero result.** [3](#0-2) 

Every call to `sign_transfer` for this transfer panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. The MPC signing call is never reached.

**Step 4 – No cancel or refund path exists.**

`remove_transfer_message` is only called inside `sign_transfer_callback` when the MPC call succeeds and the fee is zero: [4](#0-3) 

`remove_transfer_message_without_refund` is called only on storage-balance failure inside `init_transfer_internal`: [5](#0-4) 

Neither path is reachable when `sign_transfer` itself panics before the MPC call. There is no user-callable cancel function anywhere in the contract.

**Second entry path via `update_transfer_fee`:** [6](#0-5) 

A user can set `fee = amount - 1` (satisfies `fee < amount`), reducing the net amount to `1`. For any token with `origin_decimals > decimals`, `normalize_amount(1, decimals)` = `0`, driving an existing transfer of any size into the permanently stuck state.

## Impact Explanation

Tokens transferred via `ft_transfer_call` are either locked in the bridge contract (native tokens) or burned (bridge-deployed tokens) during `init_transfer_internal`: [7](#0-6) 

When `sign_transfer` permanently panics, native tokens remain locked in the contract forever and bridge tokens are burned with no corresponding mint on the destination chain. This is a permanent, irrecoverable loss of user funds — matching the critical allowed impact of **permanent freezing of bridged funds** and **decimal/normalization abuse that changes user or protocol balances**.

## Likelihood Explanation

The condition is reachable by any unprivileged user through the public `ft_transfer_call` → `init_transfer` path. It is especially likely for high-decimal NEAR tokens (24 decimals) bridging to 18-decimal EVM chains, where the normalization divisor is `10^6`. A user depositing fewer than `1_000_000` base units (a plausible dust amount) triggers the bug. The `update_transfer_fee` path additionally allows a user to self-inflict the condition on an existing transfer of any size. No special privileges, leaked keys, or external oracle manipulation are required.

## Recommendation

Add a normalization check inside `init_transfer` after building the `TransferMessage` and before locking tokens. The token decimals are already stored in `self.token_decimals` and can be looked up at this point:

```rust
if let Some(token_address) = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let net = transfer_message.amount_without_fee()
            .near_expect(BridgeError::InvalidFee);
        require!(
            Self::normalize_amount(net, decimals) > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
    }
}
```

Apply the same guard inside `update_transfer_fee` when the new fee is accepted, to prevent an existing transfer from being driven into the unrecoverable state.

## Proof of Concept

1. Register a NEAR token with `origin_decimals = 24`, `decimals = 18` (normalization divisor = `10^6`).
2. Alice calls `ft_transfer_call` with `amount = 500_000` and `fee = 0`.
3. `init_transfer` passes: `0 < 500_000`. Tokens are locked in the bridge. A `TransferMessage` is stored in `pending_transfers`.
4. A trusted relayer calls `sign_transfer` for Alice's transfer.
5. `normalize_amount(500_000, {decimals:18, origin_decimals:24})` = `500_000 / 1_000_000` = `0`.
6. `require!(0 > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. The MPC signing call is never made. The transfer message remains in `pending_transfers` permanently.
8. Alice's 500,000 base units are locked in the bridge with no recovery path.

A unit test can be written against the existing test harness in `near/omni-bridge/src/tests/lib_test.rs` by inserting a `token_decimals` entry with `origin_decimals = 24, decimals = 18`, calling `sign_transfer_callback` with a net amount below `10^6`, and asserting the panic message is `ERR_INVALID_AMOUNT_TO_TRANSFER` while the transfer message remains in storage.

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1846-1847)
```rust
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
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
