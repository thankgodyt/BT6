### Title
User Funds Permanently Burned/Locked When `normalize_amount` Returns Zero Due to Missing Pre-Transfer Validation - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `init_transfer_internal` function burns or locks user tokens before any check that the decimal-normalized transfer amount is non-zero. When `sign_transfer` is later called by a relayer, it rejects the transfer with `InvalidAmountToTransfer` if the normalized amount is 0, but the tokens are already permanently consumed with no refund or cancel mechanism.

### Finding Description
The bridge normalizes token amounts when transferring between chains with different decimal precisions using floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token with `origin_decimals = 24` (NEAR) and `decimals = 18` (EVM), `diff_decimals = 6`, so any `amount_without_fee < 1_000_000` normalizes to 0.

The critical ordering flaw is:

**Step 1 — `init_transfer` / `init_transfer_internal`:** Tokens are burned/locked and the transfer message is stored. The only validation is `fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

No check is made that `normalize_amount(amount_without_fee, decimals) > 0`.

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
```

**Step 2 — `sign_transfer`:** The normalized amount is checked, but only after tokens are already consumed:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

When this `require!` panics, the `sign_transfer` transaction reverts atomically — but the prior `init_transfer` transaction (which burned/locked the tokens and stored the message) is a separate, already-committed transaction. The transfer message remains permanently stored and the tokens are permanently gone.

There is no `cancel_transfer` or user-accessible refund path. The transfer message is only removed by `sign_transfer_callback` (requires successful MPC signing) or `claim_fee_callback` (requires on-chain finalization proof), neither of which is reachable when `sign_transfer` always panics for this transfer.

### Impact Explanation
Any user who initiates a transfer where `amount_without_fee < 10^(origin_decimals - decimals)` suffers:
- Permanent burn (deployed/bridged tokens) or permanent lock (native tokens) of their full `amount`
- A transfer message permanently stuck in contract storage
- No ability to recover funds — no cancel, no refund, no alternative completion path

This is a permanent, irrecoverable loss of bridged funds, matching the "escrow mis-accounting / decimal normalization abuse" impact class.

### Likelihood Explanation
The condition is reachable whenever:
1. A token pair has `origin_decimals > decimals` (e.g., any NEAR-native 24-decimal token bridged to an 18-decimal EVM chain — a standard configuration)
2. A user sends `amount_without_fee < 10^(origin_decimals - decimals)` — for a 6-decimal gap, any amount below 1,000,000 base units (i.e., below 0.000001 of the 18-decimal representation)

This can occur accidentally (user testing with a small amount, UI rounding, dust sweeps) or through any path that does not enforce a minimum bridgeable amount. The `init_transfer` entry point is publicly reachable by any whitelisted token holder via `ft_transfer_call`.

### Recommendation
Add the normalization check at `init_transfer` time, before tokens are consumed. The destination-chain token address and its `Decimals` struct are already available in the contract's `token_decimals` map at that point:

```rust
// Inside init_transfer, after building transfer_message and before init_transfer_internal:
if let Some(token_address) = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
) {
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

### Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (standard NEAR→EVM pair).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`, recipient on EVM.
3. `init_transfer` passes: `fee (0) < amount (500_000)` ✓
4. `init_transfer_internal` burns 500,000 tokens and stores the transfer message. Returns `U128(0)` (success).
5. Relayer calls `sign_transfer` for this transfer ID.
6. `normalize_amount(500_000, {decimals:18, origin_decimals:24})` = `500_000 / 1_000_000` = **0**.
7. `require!(0 > 0, ...)` panics → transaction reverts.
8. The 500,000 tokens are permanently burned. The transfer message is permanently stored. No recovery path exists. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
