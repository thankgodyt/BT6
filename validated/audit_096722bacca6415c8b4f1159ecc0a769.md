### Title
Permanent Freezing of User Funds via `normalize_amount` Returning Zero in `sign_transfer` — (`near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates a bridge transfer of a small token amount, the `sign_transfer` function panics with `InvalidAmountToTransfer` because `normalize_amount` (floor division) reduces the amount to zero. Since tokens are already locked/burned in `init_transfer` and no cancel/refund path exists, the user's funds are permanently frozen in the bridge.

### Finding Description

The bridge uses a two-step outbound flow:

**Step 1 — `init_transfer` (via `ft_on_transfer`):** The user's NEP-141 tokens are transferred to the bridge contract and a `TransferMessage` is stored in `pending_transfers`. The only guard here is that `fee < amount`; there is no minimum-amount check. [1](#0-0) 

**Step 2 — `sign_transfer` (called by relayer):** The bridge normalizes the amount from NEAR-side decimals (`origin_decimals`) to destination-chain decimals (`decimals`) using floor division: [2](#0-1) 

If `amount < 10^(origin_decimals − decimals)`, the result is `0`. The function then hard-panics: [3](#0-2) 

Because `sign_transfer` panics **before** calling the MPC signer, `sign_transfer_callback` is never reached, so `remove_transfer_message` is never called. The transfer stays in `pending_transfers` indefinitely with no user-accessible cancel or refund path. [4](#0-3) 

### Impact Explanation

The user's tokens are permanently frozen inside the bridge. Every subsequent relayer call to `sign_transfer` for that `transfer_id` will also panic (the normalized amount is always 0 for that fixed stored amount), so the transfer can never be completed or cancelled without DAO intervention. This matches the critical impact category: **permanent freezing of bridged funds**.

### Likelihood Explanation

Any token registered with `origin_decimals > decimals` (e.g., a NEAR-native token with 24 decimals bridged to an EVM chain where it is registered with 18 decimals — a 6-decimal gap) is affected. A user sending fewer than `10^6` raw units of such a token triggers the freeze. This is a realistic scenario for tokens with high decimal precision or for users sending dust amounts. The `init_transfer` entry point is fully permissionless. [5](#0-4) 

### Recommendation

Add a minimum-amount guard in `init_transfer` (before tokens are locked) that rejects transfers whose normalized amount would be zero:

```rust
let normalized = Self::normalize_amount(amount.0, decimals);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

Alternatively, in `sign_transfer`, instead of panicking, refund the stored amount back to the original sender and remove the pending transfer. The panic-on-zero pattern is the direct analog of the `revert MinAmountToDepositError()` in the reference report; the fix is the same: convert the hard revert into a graceful early return with fund recovery.

### Proof of Concept

1. Admin registers a token with `origin_decimals = 24`, `decimals = 18` (6-decimal gap, common for bridging NEAR-native tokens to EVM).
2. User calls `ft_transfer_call` transferring `500_000` raw units (less than `10^6`) with a valid `InitTransferMsg` targeting an EVM chain.
3. `init_transfer` succeeds — tokens are locked, `TransferMessage` stored in `pending_transfers`.
4. Relayer calls `sign_transfer` for that `transfer_id`.
5. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 }) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` panics — transaction reverts, no state change.
7. Steps 4–6 repeat forever; the `500_000` raw units are permanently locked in the bridge. [5](#0-4) [2](#0-1)

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

**File:** near/omni-bridge/src/lib.rs (L655-668)
```rust
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
