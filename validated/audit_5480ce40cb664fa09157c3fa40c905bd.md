### Title
Permanent Fund Lock via `normalize_amount` Rounding to Zero in `sign_transfer` — (`near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR-outbound transfer with an amount smaller than the decimal-scaling factor between origin and destination chains, `normalize_amount` returns `0`. The `sign_transfer` function then panics with `InvalidAmountToTransfer`. Because token locking occurs in a prior, already-committed transaction (`init_transfer`), the user's funds are permanently frozen in `pending_transfers` with no cancel or refund path.

---

### Finding Description

The bridge's outbound flow is split across two separate NEAR transactions:

**Step 1 — `init_transfer` (via `ft_on_transfer`):** Tokens are locked/burned and the `TransferMessage` is stored in `pending_transfers`. [1](#0-0) 

The only validation on `amount` at this stage is that `fee < amount`. There is no check that the amount is large enough to survive decimal normalization.

**Step 2 — `sign_transfer` (trusted-relayer only):** The bridge normalizes the net amount for the destination chain: [2](#0-1) 

`normalize_amount` performs integer floor division: [3](#0-2) 

If `amount - fee < 10^(origin_decimals - decimals)`, the result is `0`. The subsequent `require!(amount_to_transfer > 0, …)` panics the transaction. Because `sign_transfer` is a separate transaction from `init_transfer`, the panic only reverts `sign_transfer`'s own state changes — the lock from `init_transfer` is already committed and remains.

The `sign_transfer` function is gated by `#[trusted_relayer]`, so the user cannot call it themselves to trigger any recovery. No `cancel_transfer` or user-callable refund function is visible in the contract.

---

### Impact Explanation

User funds are permanently frozen in `pending_transfers`. The relayer has no incentive to retry (every attempt panics). The user has no mechanism to reclaim their tokens. This constitutes permanent freezing of bridged funds, which is within the Critical impact scope.

---

### Likelihood Explanation

Any token pair where `origin_decimals - decimals ≥ 1` is susceptible. A concrete realistic case: a token with 24 NEAR-side decimals bridging to an EVM chain where it is registered with 6 decimals (`diff = 18`). Any transfer of fewer than `10^18` base units (i.e., less than 1 full token in NEAR representation) normalizes to `0`. Users routinely transfer fractional token amounts, making this reachable without any special attacker setup — a regular user sending a small amount triggers it inadvertently.

---

### Recommendation

Add a pre-lock validation in `init_transfer` (or in `ft_on_transfer` before locking) that computes `normalize_amount(amount - fee, decimals)` and rejects the transfer if the result is `0`. Alternatively, implement a user-callable `cancel_transfer` that refunds locked tokens for transfers that have not yet been signed.

---

### Proof of Concept

1. Token is registered with `origin_decimals = 24`, `decimals = 6` (decimal diff = 18).
2. User calls `ft_on_transfer` transferring `amount = 5 × 10^17` (0.5 of the smallest NEAR-side whole unit), `fee = 0`.
3. `init_transfer` passes the `fee < amount` check, locks `5 × 10^17` tokens, stores the `TransferMessage` in `pending_transfers`. State committed.
4. Trusted relayer calls `sign_transfer`.
5. `normalize_amount(5 × 10^17, {origin: 24, dest: 6})` = `5 × 10^17 / 10^18` = `0` (floor division).
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics — `sign_transfer` reverts.
7. `pending_transfers` still holds the message; tokens remain locked forever with no recovery path. [4](#0-3) [2](#0-1) [1](#0-0)

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
