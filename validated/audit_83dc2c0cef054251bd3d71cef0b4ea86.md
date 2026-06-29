All cited code references are confirmed against the actual repository. Here is my assessment:

---

Audit Report

## Title
Permanently Un-Executable NEAR→Foreign Transfer Due to Missing Decimal-Normalization Guard at Transfer Creation — (`File: near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` only validates `fee < amount` but does not verify that `normalize_amount(amount - fee, decimals) > 0`. A user can lock tokens in a transfer where the net amount after fee deduction is below the decimal-normalization divisor, causing every subsequent `sign_transfer` call to panic with `InvalidAmountToTransfer`. Because no cancellation or refund path exists and `update_transfer_fee` only permits fee increases, the locked tokens are permanently irrecoverable.

## Finding Description
`normalize_amount` performs floor division: [1](#0-0) 

`sign_transfer` enforces a post-normalization non-zero check: [2](#0-1) 

`init_transfer` only checks `fee < amount`, with no normalization guard: [3](#0-2) 

When `1 ≤ (amount - fee) < 10^(origin_decimals - decimals)`, the transfer is stored and tokens are locked, but `normalize_amount` returns `0` at signing time, causing `sign_transfer` to panic before the MPC call is ever made. `sign_transfer_callback` is therefore never reached, so `remove_transfer_message` is never called: [4](#0-3) 

`update_transfer_fee` enforces `fee.fee >= current_fee.fee`, meaning the fee can only be raised, which shrinks `amount - fee` further and cannot rescue the transfer: [5](#0-4) 

No `cancel_transfer` or `refund_transfer` function exists anywhere in the contract. The SECURITY.md comment at line 2781–2782 acknowledges that dust can be locked when `fee = 0`, but does not address the case where the entire net amount normalizes to zero. [6](#0-5) 

## Impact Explanation
This constitutes **permanent freezing of bridged funds**, which is explicitly within the Critical impact scope. The user's tokens are locked in the NEAR bridge contract with no on-chain recovery path. Every `sign_transfer` call for the affected `transfer_id` reverts; the transfer message and the escrowed tokens remain in the contract indefinitely.

## Likelihood Explanation
Any user who calls `ft_transfer_call` → `init_transfer` with a net amount `(amount - fee)` below the normalization threshold triggers this condition. No special privilege is required to create the transfer. For a 6-decimal gap (e.g., `origin_decimals = 24`, `decimals = 18`), the threshold is 10^6 raw units; for a 2-decimal gap it is only 100 raw units. The condition is reachable without any special privilege. Likelihood is **medium**.

## Recommendation
Add a normalization guard inside `init_transfer_internal` immediately after the existing fee check:

```rust
// After: require!(transfer_message.fee.fee < transfer_message.amount, ...)
if let Some(token_address) = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        require!(
            Self::normalize_amount(
                transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
                decimals,
            ) > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
    }
}
```

Alternatively, implement a `cancel_transfer` function that allows the original sender to reclaim locked tokens for transfers that have not yet been signed.

## Proof of Concept
Assume a token registered with `origin_decimals = 20`, `decimals = 18` (divisor = 100).

1. Alice calls `ft_transfer_call` with `amount = 150`, `fee = 100`.
2. `init_transfer` checks `100 < 150` → passes. Transfer stored; 150 tokens locked.
3. Trusted relayer calls `sign_transfer` for Alice's `transfer_id`.
4. `amount_without_fee() = 150 - 100 = 50`.
5. `normalize_amount(50, {decimals:18, origin_decimals:20}) = 50 / 100 = 0`.
6. `require!(0 > 0, ...)` → panics with `InvalidAmountToTransfer`.
7. No callback fires; `remove_transfer_message` is never called.
8. Alice's 150 tokens remain locked forever. `update_transfer_fee` cannot help because it only allows increasing the fee (making `amount - fee` even smaller).

### Citations

**File:** near/omni-bridge/src/lib.rs (L398-402)
```rust
                let current_fee = transfer.message.fee;
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

**File:** near/omni-bridge/src/lib.rs (L648-668)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
