### Title
Decimal Normalization Truncation to Zero Permanently Freezes Bridged Funds - (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts and locks user tokens without validating that the post-normalization transfer amount is non-zero. `sign_transfer` later rejects such transfers with `InvalidAmountToTransfer`, creating an irrecoverable state where user funds are permanently frozen in the bridge with no refund path.

### Finding Description

`normalize_amount` uses floor division to convert a NEAR-side token amount to the destination chain's decimal precision:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

When a user initiates a transfer via `ft_transfer_call` → `init_transfer`, the only fee validation performed is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [2](#0-1) 

There is **no check** that `normalize_amount(amount - fee) > 0`. If the net amount is smaller than `10^(origin_decimals - decimals)`, it normalizes to zero via floor division.

When a relayer subsequently calls `sign_transfer`, it computes the normalized amount and enforces:

```rust
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [3](#0-2) 

This `require!` panics, reverting the entire `sign_transfer` call. The transfer message remains in `pending_transfers` indefinitely. There is no `cancel_transfer` or refund function — `sign_transfer_callback` only removes the transfer message when the MPC signing succeeds and the fee is zero, a branch that is never reached because `sign_transfer` panics before the MPC call. [4](#0-3) 

### Impact Explanation

User tokens are permanently locked in the bridge contract. The `init_transfer_internal` function returns `U128(0)` (zero refund) on success, meaning the NEP-141 `ft_transfer_call` does not return the tokens to the sender. Once locked, the transfer can never be signed (always panics), never finalized, and never refunded. This constitutes **permanent freezing of bridged funds**. [5](#0-4) 

### Likelihood Explanation

This is reachable for any token registered with `origin_decimals > decimals` (e.g., a token with 24 NEAR-side decimals bridging to an 18-decimal EVM chain, where the decimal difference is 6). Any transfer of fewer than `10^6` base units (i.e., less than 1 full token in that example) will normalize to zero. A user sending a small or "dust" amount — a common pattern — triggers this permanently. No special privileges are required; any unprivileged user calling `ft_transfer_call` is the entry point. [6](#0-5) 

### Recommendation

Add a normalization check inside `init_transfer` before accepting and locking tokens:

```rust
let token_address = self.get_token_address(
    init_transfer_msg.get_destination_chain(),
    self.get_token_id(&OmniAddress::Near(token_id.clone())),
);
if let Some(addr) = token_address {
    if let Some(decimals) = self.token_decimals.get(&addr) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This mirrors the existing guard in `sign_transfer` and prevents the irrecoverable locked-funds state.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (6-decimal difference, factor of `10^6`).
2. Alice calls `ft_transfer_call` with `amount = 500_000` (less than `10^6`) and `fee = 0`.
3. `init_transfer` passes the `fee < amount` check, locks 500,000 units, stores the transfer message, and returns `U128(0)` — Alice's tokens are taken.
4. A relayer calls `sign_transfer` for Alice's transfer ID.
5. `normalize_amount(500_000, {origin: 24, dest: 18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` panics → transaction reverts, transfer message stays in storage.
7. Step 4–6 repeats forever. Alice's 500,000 units are permanently frozen. [6](#0-5) [1](#0-0) [2](#0-1)

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
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
