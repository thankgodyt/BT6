### Title
Floor Division in `normalize_amount` Permanently Freezes User Funds When Transfer Amount Is Below Decimal Threshold - (File: near/omni-bridge/src/lib.rs)

### Summary
`normalize_amount` uses integer floor division to scale a token amount from its origin precision to the bridge's normalized precision. When a user initiates a transfer whose `amount_without_fee` is smaller than `10^(origin_decimals - decimals)`, the division truncates to zero. The subsequent `require!(amount_to_transfer > 0)` guard in `sign_transfer` then permanently reverts every signing attempt, while the user's tokens are already locked or burned with no cancellation path.

### Finding Description
`normalize_amount` is defined as:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

`sign_transfer` calls this function on `amount_without_fee` and immediately panics if the result is zero:

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

The `init_transfer` path only validates that `fee.fee < amount`; it does not verify that `amount_without_fee >= 10^diff_decimals`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

After `init_transfer_internal` succeeds, the tokens are already locked or burned and the `TransferMessage` is stored: [4](#0-3) 

There is no `cancel_transfer` or user-callable refund path. The only code paths that remove a `TransferMessage` are `claim_fee_callback` (requires a valid destination-chain proof) and `sign_transfer_callback` (only reached after a successful MPC signing, which never happens because `sign_transfer` panics first). [5](#0-4) [6](#0-5) 

### Impact Explanation
Any user who sends a token amount whose `amount_without_fee` is less than `10^(origin_decimals - decimals)` will have their tokens permanently frozen in the bridge. For a token registered with `origin_decimals = 24` and `decimals = 18` (a realistic 6-decimal gap), any transfer of fewer than 1,000,000 base units (minus fee) triggers this. The tokens are burned or locked on NEAR, the `TransferMessage` persists in contract storage, and every subsequent `sign_transfer` call reverts with `InvalidAmountToTransfer`. The funds are irrecoverable. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation
The condition is reachable by any unprivileged user who calls `ft_transfer_call` with a small amount. No special role or privileged access is required. Tokens with a decimal gap between origin and bridge representation (e.g., 24-decimal Solana tokens normalized to 18) are explicitly supported by the bridge. A user unfamiliar with the minimum effective transfer size, or one who deliberately sends a sub-threshold amount, will trigger the freeze. The `init_transfer` validation does not prevent it.

### Recommendation
Add a minimum-amount check inside `init_transfer` (before tokens are locked/burned) that verifies `normalize_amount(amount_without_fee, decimals) > 0`. Alternatively, add a user-callable `cancel_transfer` function that refunds locked/burned tokens when a transfer has not yet been signed, so that stuck transfers can be recovered.

### Proof of Concept
1. A token is registered with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`, divisor = 1,000,000).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000`). Tokens are burned/locked. `TransferMessage` is stored.
4. Relayer calls `sign_transfer`.
5. `normalize_amount(500_000, {origin_decimals:24, decimals:18})` = `500_000 / 1_000_000` = **0**.
6. `require!(0 > 0, ...)` panics with `InvalidAmountToTransfer`.
7. No MPC signing occurs; `sign_transfer_callback` is never reached; the `TransferMessage` is never removed.
8. The user's 500,000 base-unit tokens are permanently frozen with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L656-658)
```rust
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
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
