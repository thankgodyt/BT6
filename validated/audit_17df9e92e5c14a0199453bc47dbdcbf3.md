Audit Report

## Title
Sub-Threshold Amount Permanently Freezes Locked Tokens in `sign_transfer` — (`near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` accepts any amount strictly greater than the fee, but `sign_transfer` requires that `normalize_amount(amount − fee) > 0`. When a user locks tokens whose net amount (after fee) is smaller than the decimal-normalization divisor (`10^(origin_decimals − decimals)`), `sign_transfer` always panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. No cancel or refund path exists for pending transfers, so the locked tokens are permanently frozen.

## Finding Description

**Root cause — missing pre-condition in `init_transfer`:**

`init_transfer` (lines 554–557) only enforces `fee.fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

It does **not** verify that `normalize_amount(amount − fee) > 0`.

**Blocking check in `sign_transfer`:**

`sign_transfer` (lines 475–485) computes the on-chain normalized amount and then hard-panics if it is zero:

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

**`normalize_amount` uses floor division:**

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a NEAR-native token (`origin_decimals = 24`) bridging to an EVM token (`decimals = 18`), the divisor is `10^6`. Any net amount below `1_000_000` yocto-units normalizes to `0`.

**No recovery path:**

`remove_transfer_message` is only called inside `sign_transfer_callback` (when fee is zero and MPC signing succeeds) and `claim_fee_callback` (which requires a proof of finalization on the destination chain). Neither is reachable when `sign_transfer` itself panics. There is no public `cancel_transfer` or admin rescue function.

**Exploit flow:**

1. User calls `ft_transfer_call` on the token contract, routing to `omni-bridge` with `amount = 1` (or any value below the normalization threshold) and `fee = 0`.
2. `init_transfer` passes the `fee < amount` check, increments the nonce, stores the `TransferMessage` in `pending_transfers`, and locks the tokens.
3. Any trusted relayer calls `sign_transfer` for this transfer ID.
4. `normalize_amount(1, {origin: 24, dest: 18}) = 0` → `require!(0 > 0, …)` panics.
5. The call reverts; the pending transfer entry and the locked tokens remain.
6. Step 3–5 repeat forever. The tokens are permanently frozen.

## Impact Explanation

Permanent freezing of bridged funds on NEAR. The locked tokens can never be unlocked, minted on the destination chain, or refunded to the sender. This matches the Critical impact class: *permanent freezing of bridged funds across NEAR or EVM flows*.

## Likelihood Explanation

Any unprivileged user can trigger this by sending a sub-threshold amount through the standard `ft_transfer_call` → `init_transfer` path. No special role, leaked key, or external dependency is required. The threshold is token-specific: for tokens with a large decimal gap (e.g., 24 NEAR decimals → 6 destination decimals, divisor = `10^18`), even amounts that appear non-trivial to a user can fall below the threshold. The action is irreversible once the `ft_transfer_call` completes.

## Recommendation

Add a normalization check inside `init_transfer`, immediately after the fee check, before tokens are locked:

```rust
let token_address = self
    .get_token_address(transfer_message.get_destination_chain(), ...)
    .near_expect(BridgeError::TokenNotFound);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee()
            .near_expect(BridgeError::InvalidFee),
        decimals,
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the existing guard in `sign_transfer` and rejects the transfer before any tokens are locked, returning them to the sender via the NEP-141 refund mechanism.

## Proof of Concept

**Unit test plan (local, no mainnet):**

1. Deploy the `omni-bridge` contract in a `near-workspaces` sandbox.
2. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = `10^6`).
3. Call `ft_transfer_call` with `amount = 500_000` (below threshold) and `fee = 0`.
4. Assert the transfer is stored in `pending_transfers` and the token balance of the bridge increased by `500_000`.
5. Call `sign_transfer` for the resulting `TransferId` from a trusted relayer account.
6. Assert the call panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Assert the pending transfer still exists and the tokens remain locked (no refund issued).
8. Confirm no public function can remove the pending entry or recover the tokens.