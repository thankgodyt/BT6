### Title
Precision Loss in `normalize_amount` Permanently Locks User Tokens When Transfer Amount Falls Below Decimal Threshold — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR-to-foreign-chain transfer for a token whose `origin_decimals` exceeds the registered destination `decimals`, and the net transfer amount (amount minus fee) is smaller than `10^(origin_decimals − decimals)`, the `normalize_amount` helper returns `0` via floor division. The subsequent `sign_transfer` call panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because the user's tokens were already locked in the bridge during `ft_on_transfer` and no public cancel/refund path exists, those tokens are permanently frozen.

---

### Finding Description

`normalize_amount` performs integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

When `amount < 10^diff_decimals`, the result is `0`. The code's own comment acknowledges this: *"When fee = 0, dust stays locked/burned."* However, the comment treats this as a dust-remainder edge case, not as the scenario where the **entire** transfer amount normalizes to zero.

In `sign_transfer`, the normalized amount is checked immediately after computation:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

This panic happens **after** the user's tokens have already been accepted and stored in `pending_transfers` via `ft_on_transfer`. There is no public-facing function to cancel a pending transfer and return the locked tokens. The internal `remove_transfer_message` is only reachable through `claim_fee_callback` (which requires a proof from the destination chain that can never exist for an unsigned transfer) and `fin_transfer_callback` (which also requires a finalized proof). [3](#0-2) 

No minimum-amount guard exists at transfer initiation time to reject amounts that would normalize to zero before the tokens are locked.

---

### Impact Explanation

Any user who sends a token amount (net of fee) smaller than `10^(origin_decimals − decimals)` from NEAR to a foreign chain will have their tokens permanently frozen in the bridge. No relayer can ever successfully call `sign_transfer` for that transfer ID; every attempt panics. No on-chain path exists for the user to reclaim the locked balance. This constitutes **permanent freezing of bridged funds**, matching the critical impact class.

---

### Likelihood Explanation

The condition is reachable by any unprivileged bridge user. Tokens bridged between chains with large decimal differences (e.g., a NEAR-native token with 24 decimals registered on an EVM chain with 6 decimals, giving `diff_decimals = 18`) have a minimum transferable unit of `10^18`. A user sending any amount below that threshold — a plausible mistake given that NEAR token balances are displayed in yocto units — triggers the freeze. No special role or privileged access is required; the user only needs to call `ft_transfer_call` on the token contract with a small amount.

---

### Recommendation

1. **Enforce a minimum amount at initiation time**: In `ft_on_transfer` / `init_transfer_internal`, look up the token's `Decimals` and reject (refund) any transfer whose `amount_without_fee()` is less than `10^(origin_decimals − decimals)`, returning the full amount to the caller per the NEP-141 refund convention.
2. **Add a public `cancel_transfer` function**: Allow the original sender to cancel a pending transfer that has not yet been signed, burning or unlocking the locked tokens and returning them to the user. This also serves as a general safety valve for stuck transfers.
3. **Alternatively**, enforce `_newFractionSupply`-style minimum: require that `decimals.origin_decimals − decimals.decimals` never exceeds a safe bound, or that the registered `decimals` value is always equal to `origin_decimals` (no normalization), eliminating the precision-loss class entirely.

---

### Proof of Concept

**Setup**: Token registered with `origin_decimals = 24`, `decimals = 6` (`diff_decimals = 18`). Minimum transferable unit = `10^18`.

**Steps**:
1. User calls `ft_transfer_call` on the token contract with `amount = 5 × 10^17` (0.5 of the minimum unit) and `fee = 0`.
2. Bridge's `ft_on_transfer` accepts the tokens, stores the `TransferMessage` in `pending_transfers`, and returns `0` (no refund).
3. Relayer calls `sign_transfer(transfer_id, ...)`.
4. Inside `sign_transfer`:
   - `amount_without_fee()` = `5 × 10^17`
   - `normalize_amount(5×10^17, {origin_decimals:24, decimals:6})` = `5×10^17 / 10^18` = **0**
   - `require!(0 > 0, ...)` → **panic: ERR_INVALID_AMOUNT_TO_TRANSFER**
5. Every subsequent relayer call for this `transfer_id` panics identically.
6. `claim_fee_callback` and `fin_transfer_callback` are unreachable (no signed payload, no destination proof).
7. The user's `5 × 10^17` tokens remain permanently locked in the bridge. [4](#0-3) [2](#0-1)

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

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
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
