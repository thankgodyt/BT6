Audit Report

## Title
`init_transfer` Locks Tokens Without Validating `normalize_amount(amount - fee) > 0`, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` accepts and locks user tokens after only checking `fee < amount`, without verifying that the net amount survives decimal normalization to a non-zero value. `sign_transfer` enforces this check but panics before making the MPC call, so `sign_transfer_callback` is never reached and `remove_transfer_message` is never invoked. With no public cancellation path, the locked tokens are permanently frozen.

## Finding Description

The two-step outbound flow is: `init_transfer` (stores `TransferMessage`, locks tokens) → `sign_transfer` (requests MPC signature).

`init_transfer` at [1](#0-0)  only checks:
```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

`sign_transfer` at [2](#0-1)  enforces:
```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()..., decimals);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

`normalize_amount` performs floor division: [3](#0-2) 

When `origin_decimals > decimals` (e.g., 24 vs 6, diff = 18), any `amount - fee < 10^18` normalizes to 0. `sign_transfer` panics at the `require!` before the MPC call is ever dispatched, so `sign_transfer_callback` is never invoked.

`sign_transfer_callback` at [4](#0-3)  only calls `remove_transfer_message` on a successful MPC response (`if let Ok(signature) = call_result`). Since `sign_transfer` panics before dispatching the MPC call, this callback path is unreachable for the affected transfer.

No public `cancel_transfer` or admin escape hatch exists. The `TransferMessage` remains in `pending_transfers` indefinitely and the locked token balance is never released.

## Impact Explanation

This directly matches the Critical allowed impact: **permanent freezing of bridged funds**. User tokens are locked in the NEAR `omni-bridge` contract with no recovery path. The `TransferMessage` is stored in a prior transaction; the subsequent `sign_transfer` always panics for sub-threshold amounts, and no other function removes the message or refunds the tokens.

## Likelihood Explanation

Any token pair where `origin_decimals > decimals` creates a minimum transferable unit of `10^(origin_decimals - decimals)`. For a 24-decimal NEAR token bridged to a 6-decimal EVM token, the minimum is `10^18`. Amounts below this threshold — a realistic user mistake with no on-chain rejection at `init_transfer` — permanently lose funds. Additionally, `update_transfer_fee` at [5](#0-4)  allows the sender to raise the token fee post-initiation (only constrained by `fee < amount`), which can push a previously valid `amount - fee` below the normalization threshold, triggering the same freeze on an already-initiated transfer. Any unprivileged user can trigger this via `ft_transfer_call` → `init_transfer`.

## Recommendation

Add the normalization check inside `init_transfer` (after the `fee < amount` check) before storing the `TransferMessage`. Look up the token's destination address and decimals for the target chain, then call `Self::normalize_amount(transfer_message.amount_without_fee()..., decimals)` and `require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref())`. Apply the same guard inside `update_transfer_fee` when the token fee is raised, to prevent a valid transfer from becoming un-signable after the fact.

## Proof of Concept

1. Deploy a NEAR token with `origin_decimals = 24`; bind it to an EVM address with `decimals = 6` via `bind_token`.
2. Call `ft_transfer_call` with `amount = 999_999_999_999_999_999` (< 10^18) and `msg` encoding `InitTransferMsg { fee: U128(0), native_token_fee: U128(0), recipient: <EVM address> }`.
3. Observe `init_transfer` succeeds at [1](#0-0)  — tokens are deducted from the user and locked.
4. Call `sign_transfer` with the resulting `transfer_id`.
5. Observe the call panics at [6](#0-5)  with `ERR_INVALID_AMOUNT_TO_TRANSFER` because `normalize_amount(999_999_999_999_999_999, {24, 6}) = 0`.
6. Confirm `sign_transfer_callback` is never reached (no MPC call was dispatched), `remove_transfer_message` is never called, and no other public function can recover the locked tokens.

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

**File:** near/omni-bridge/src/lib.rs (L649-668)
```rust
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
