### Title
Missing Normalized-Amount Guard in `init_transfer` Causes Permanent Token Loss - (File: near/omni-bridge/src/lib.rs)

### Summary

The NEAR `omni-bridge` contract accepts and finalizes an outbound transfer (`init_transfer`) without verifying that the post-fee amount survives decimal normalization. When the normalized amount rounds to zero, the user's tokens are irreversibly burned or locked, the pending transfer record is stored permanently, and no relayer can ever complete or cancel the transfer.

### Finding Description

**Vulnerability class:** Balance manipulation / escrow mis-accounting — the contract does not revert when the effective transfer amount is insufficient (normalizes to zero), directly analogous to the yAxis H-04 pattern.

**Root cause — two-step validation gap:**

Step 1 — `init_transfer` validates only that `fee < amount`: [1](#0-0) 

Step 2 — tokens are immediately burned/locked inside `init_transfer_internal`: [2](#0-1) 

Step 3 — the normalization check only happens later, inside `sign_transfer`, called by a trusted relayer: [3](#0-2) 

The `normalize_amount` helper uses floor division: [4](#0-3) 

If `amount_without_fee < 10^(origin_decimals − decimals)`, the result is `0`. For a token registered with `origin_decimals = 24` and `decimals = 18` (a common NEAR-to-EVM pairing), any `amount_without_fee < 1_000_000` normalizes to zero.

**No recovery path exists.** When `sign_transfer` panics with `InvalidAmountToTransfer`, the transfer message is never removed: [5](#0-4) 

`remove_transfer_message` is only called inside `sign_transfer_callback` on a *successful* MPC signature when `fee.is_zero()`. A panicking `sign_transfer` never reaches the callback, so the record is orphaned and the burned/locked tokens are unrecoverable.

### Impact Explanation

A user who sends `amount = 999_999` yoctoNEAR (or any token amount below the minimum representable unit on the destination chain) with `fee = 0` will:

1. Have their tokens burned/locked by `init_transfer_internal`.
2. Receive a stored `TransferMessage` that no relayer can ever finalize.
3. Permanently lose their funds with no on-chain refund or cancel path.

This matches the allowed critical impact: *permanent freezing / loss of bridged funds*.

### Likelihood Explanation

- Tokens with large decimal differences (e.g., NEAR 24 → EVM 18, diff = 6, threshold = 1 000 000 units) are already deployed on mainnet.
- A user sending a "dust" amount, a UI rounding error, or a programmatic transfer that computes a small residual after fee subtraction can all trigger this silently.
- The contract emits an `InitTransferEvent` log, giving the user false confidence that the transfer is in progress.
- No minimum-amount UI hint or on-chain guard exists at initiation time.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) **before** burning/locking tokens:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the guard already present in `sign_transfer` but moves it to the point where the user's funds are still safe.

### Proof of Concept

**Setup:** Token registered with `origin_decimals = 24`, `decimals = 18` (diff = 6, threshold = 1 000 000).

```
User calls ft_transfer_call:
  amount = 500_000          // < 1_000_000 threshold
  fee    = 0                // fee < amount ✓ — passes init_transfer guard

init_transfer_internal:
  burn_tokens_if_needed(token, 500_000)   // tokens destroyed
  lock_tokens_if_needed(...)              // locked on origin chain
  store TransferMessage                   // stored permanently
  return U128(0)                          // ft_transfer_call keeps tokens

Relayer calls sign_transfer:
  amount_without_fee = 500_000
  normalize_amount(500_000, {24,18}) = 500_000 / 1_000_000 = 0
  require!(0 > 0) → PANIC "ERR_INVALID_AMOUNT_TO_TRANSFER"

Result:
  - 500_000 tokens burned/locked permanently
  - TransferMessage orphaned in storage
  - No refund, no cancel, no completion possible
``` [1](#0-0) [6](#0-5) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L648-667)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
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
