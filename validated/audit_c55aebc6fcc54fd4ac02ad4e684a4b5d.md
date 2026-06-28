### Title
Tokens Permanently Burned/Locked When Transfer Amount Normalizes to Zero — (File: `near/omni-bridge/src/lib.rs`)

### Summary
`init_transfer` burns or locks user tokens and commits the origin nonce before any check that the amount, after decimal normalization, is non-zero. When a user sends an amount below the normalization threshold, `normalize_amount` returns 0, and every subsequent `sign_transfer` call reverts with `InvalidAmountToTransfer`. Because the burn/lock occurs in an already-committed transaction, the tokens are permanently lost with no recovery path.

### Finding Description
`normalize_amount` performs floor division:

```rust
// near/omni-bridge/src/lib.rs
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

For a token with `origin_decimals = 24` and `decimals = 6`, the divisor is `10^18`. Any amount below `10^18` base units normalizes to 0.

In `init_transfer`, the nonce is incremented and the transfer message is built with no normalization check: [2](#0-1) 

The only amount validation is `fee.fee < amount` — this passes for `amount = 1, fee = 0`. Then `init_transfer_internal` is called, which burns (deployed tokens) or locks (native tokens) the full raw amount: [3](#0-2) 

Later, when a relayer calls `sign_transfer`, normalization is applied and the zero-check fires:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()...
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [4](#0-3) 

This `require!` panic reverts only the `sign_transfer` transaction. The `init_transfer` state — burned/locked tokens and the stored `pending_transfers` entry — is already committed and is not rolled back. No public cancel or refund function exists to recover the stuck tokens.

### Impact Explanation
Any user who sends an amount below `10^(origin_decimals - decimals)` base units permanently loses their tokens. The tokens are burned (for deployed bridge tokens) or locked (for native tokens) in `init_transfer_internal`, but the cross-chain transfer can never be completed because every `sign_transfer` call will revert. This constitutes permanent loss of bridged funds, matching the allowed critical impact scope.

### Likelihood Explanation
The entry path is the public `ft_on_transfer` → `init_transfer` flow, callable by any token holder. For tokens with a large decimal gap (e.g., 24 → 6 decimals, divisor = `10^18`), the threshold is `10^18` base units — a small but reachable amount. No minimum-amount guard exists in `init_transfer`. A user sending a sub-threshold amount by mistake (e.g., due to UI rounding or copy-paste error) triggers the loss. The protocol's own comment acknowledges floor-division truncation: [5](#0-4) 

but does not guard against the case where the *entire* amount truncates to zero before the tokens are committed.

### Recommendation
Add a normalization check in `init_transfer` (or `init_transfer_internal`) before burning/locking tokens. If the destination-chain decimals are already registered, verify `normalize_amount(amount.0, decimals) > 0` and revert early (returning the full amount to the caller via the NEP-141 refund mechanism). Additionally, introduce a public `cancel_transfer` function so users can recover tokens from stuck pending transfers regardless of the cause.

### Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 6` on the destination chain (divisor = `10^18`).
2. Call `ft_transfer_call` on the token contract with `amount = 1` and a valid `InitTransferMsg` (fee = 0).
3. `ft_on_transfer` → `init_transfer` → `init_transfer_internal` succeeds: 1 base unit is burned, transfer message stored in `pending_transfers`, nonce incremented.
4. Relayer calls `sign_transfer` for the stored transfer ID.
5. `normalize_amount(1, {origin_decimals: 24, decimals: 6})` = `1 / 10^18` = `0`.
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics; `sign_transfer` transaction reverts.
7. The 1 base unit is permanently burned; the transfer message remains in `pending_transfers` with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L536-557)
```rust
        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
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
