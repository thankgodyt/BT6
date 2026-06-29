### Title
Decimal Normalization Floor-Division to Zero Permanently Locks User Tokens in `init_transfer_internal` — (`near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR→foreign transfer with an amount that, after `normalize_amount` floor-division, rounds down to zero, their tokens are **permanently locked or burned** inside `init_transfer_internal` with no user-accessible recovery path. The zero-amount guard exists only in `sign_transfer`, which is called by a trusted relayer *after* the tokens are already gone.

---

### Finding Description

The NEAR bridge uses `normalize_amount` to convert a NEAR-side token amount (e.g., 24 decimals) to the destination-chain precision (e.g., 18 decimals on EVM):

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))   // floor division
}
``` [1](#0-0) 

For a token with `origin_decimals = 24` and `decimals = 18`, the divisor is `10^6 = 1_000_000`. Any `amount_without_fee < 1_000_000` normalizes to **zero**.

The only guard against a zero normalized amount is inside `sign_transfer`, called by a trusted relayer:

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

However, by the time `sign_transfer` is called, `init_transfer_internal` has **already** burned or locked the user's tokens:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [3](#0-2) 

The `init_transfer` entry point only validates `fee < amount`, with no check that `normalize_amount(amount - fee) > 0`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [4](#0-3) 

When `sign_transfer` reverts with `InvalidAmountToTransfer`, the transfer message remains in `pending_transfers` indefinitely. There is no user-callable cancellation or withdrawal function to recover the locked/burned tokens.

---

### Impact Explanation

A user who sends a "dust" amount below the normalization threshold (e.g., 999,999 yoctoNEAR for a 24→18 decimal token) will have their tokens **permanently burned or locked** in the bridge contract. The transfer can never be finalized (relayer's `sign_transfer` always reverts), and no refund mechanism exists for the user. This constitutes a direct, permanent loss of bridged funds — matching the Critical impact class of balance manipulation / escrow mis-accounting.

---

### Likelihood Explanation

- Tokens bridging between NEAR (24 decimals) and EVM chains (commonly 6 or 18 decimals) are the standard case; a 24→18 decimal difference gives a divisor of 1,000,000.
- Any user sending fewer than 1,000,000 yoctoNEAR (0.000001 NEAR, worth fractions of a cent) triggers the bug.
- No front-end validation is enforced at the contract level.
- The scenario is realistic for automated scripts, bots, or users testing with small amounts.

Likelihood is **low-medium**: the dust amounts are small in absolute value, but the loss is total and unrecoverable for the affected amount.

---

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) **before** burning or locking tokens:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(token_address) = token_address {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This mirrors the existing guard in `sign_transfer` but places it at the point where the user's tokens are still safe.

---

### Proof of Concept

**Setup**: Token registered with `origin_decimals = 24`, `decimals = 18` (NEAR → Ethereum). Divisor = `10^6`.

1. User calls `ft_transfer_call(bridge, 500_000, init_transfer_msg)` with `fee = 0`, `recipient = EVM address`.
2. `ft_on_transfer` → `init_transfer` → `init_transfer_internal`:
   - `fee (0) < amount (500_000)` ✓ passes
   - `burn_tokens_if_needed(token, 500_000)` — tokens burned
   - `lock_tokens_if_needed(Eth, token, 500_000)` — locked
   - Returns `U128(0)` → NEP-141 keeps all tokens in bridge
3. Trusted relayer calls `sign_transfer(transfer_id, ...)`:
   - `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`
   - `require!(0 > 0)` → **PANIC: `ERR_INVALID_AMOUNT_TO_TRANSFER`**
4. Transfer message stays in `pending_transfers`. User's 500,000 yoctoNEAR are permanently burned. No cancellation path exists. [5](#0-4) [2](#0-1) [1](#0-0)

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
