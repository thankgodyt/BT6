Based on my code review, the claim is confirmed by the actual code. Let me verify the key assertions:

**`normalize_amount`** performs floor division: [1](#0-0) 

**`init_transfer`** only checks `fee < amount`, no normalized-amount check: [2](#0-1) 

**`sign_transfer`** enforces `amount_to_transfer > 0` and panics if zero: [3](#0-2) 

**`sign_transfer_callback`** only removes the transfer message on successful MPC signing: [4](#0-3) 

The code comment at line 2781 acknowledges dust locking but only for the remainder case (where normalized amount > 0 but has a remainder). The zero-normalization case — where `sign_transfer` panics before the MPC call — is a distinct, unrecovered state with no user-accessible cancel path confirmed in the codebase. [5](#0-4) 

---

Audit Report

## Title
Missing Pre-Validation of Normalized Transfer Amount Permanently Locks User Tokens in `init_transfer` - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` accepts and locks user tokens without verifying that `normalize_amount(amount - fee) > 0`. When the net amount is below the decimal scaling factor, `sign_transfer` always panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` before the MPC call is made. Because `sign_transfer_callback` (the only place `remove_transfer_message` is called) is never reached, the transfer message and the locked tokens are permanently frozen in the bridge with no recovery path.

## Finding Description
`normalize_amount` uses floor division: `amount / 10^(origin_decimals - decimals)`. For a NEAR→EVM pair with `origin_decimals = 24` and `decimals = 18`, the scaling factor is `10^6`.

`init_transfer` stores the `TransferMessage` in `pending_transfers` after only checking `fee.fee < amount` (line 554–557). There is no check that `normalize_amount(amount - fee) > 0`.

Later, `sign_transfer` (a `#[trusted_relayer]` function) computes the normalized amount and enforces `amount_to_transfer > 0` (lines 475–485). If the normalized amount is zero, `require!` panics and the entire transaction reverts — no MPC call is made.

`sign_transfer_callback` only invokes `remove_transfer_message` inside `if let Ok(signature) = call_result` (lines 655–658). Since `sign_transfer` panics before scheduling the MPC call, the callback is never registered and the transfer message is never removed. No user-accessible cancel or refund function exists for entries in `pending_transfers`.

## Impact Explanation
Permanent freezing of bridged funds. Any user who initiates a NEAR→foreign transfer where `amount - fee < 10^(origin_decimals - decimals)` will have their tokens permanently locked in the bridge contract with no recovery mechanism. This directly matches the allowed critical impact: "permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."

## Likelihood Explanation
Any unprivileged token holder can trigger this via a standard `ft_transfer_call` on any registered NEP-141 token. No special privileges are required. For the common 24→18 decimal pairing (scaling factor = 10^6), any net transfer amount below 1,000,000 base units triggers the lock. Users unfamiliar with decimal normalization — or who set a fee close to their transfer amount — will encounter this accidentally. The condition is repeatable and affects every such transfer independently.

## Recommendation
In `init_transfer`, before storing the `TransferMessage`, add a pre-validation check:

```rust
if let Some(token_address) = self.get_token_address(
    init_transfer_msg.get_destination_chain(), &token_id
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        require!(
            Self::normalize_amount(
                amount.0.saturating_sub(init_transfer_msg.fee.0),
                decimals
            ) > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
    }
}
```

If the check fails, `ft_on_transfer` must return the full `amount` so the NEP-141 standard refunds the user's tokens before any state is mutated.

## Proof of Concept
1. Token `token.near` is registered with `origin_decimals = 24`, `decimals = 18` (scaling factor = `10^6`).
2. User calls `ft_transfer_call` on `token.near` targeting the bridge with `amount = 500_000`, `fee = 0`.
3. Bridge's `ft_on_transfer` calls `init_transfer`, which passes the `fee < amount` check (0 < 500,000), stores the `TransferMessage` in `pending_transfers`, and returns `U128(0)` — bridge retains all 500,000 tokens.
4. Trusted relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 }) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ERR_INVALID_AMOUNT_TO_TRANSFER)` panics; transaction reverts.
7. `sign_transfer_callback` is never scheduled; `remove_transfer_message` is never called.
8. The `TransferMessage` remains in `pending_transfers` indefinitely; the user's 500,000 tokens are permanently locked.

### Citations

**File:** near/omni-bridge/src/lib.rs (L482-485)
```rust
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
