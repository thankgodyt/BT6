### Title
Decimal Normalization Dust Permanently Locked When Transfer Fee Is Zero - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `normalize_amount` function uses floor integer division to convert token amounts from higher-decimal source chains to lower-decimal destination chains. The truncated remainder ("dust") is permanently locked in the NEAR bridge contract (for native tokens) or burned (for deployed tokens) whenever a user initiates a transfer with `fee = 0`. No recovery mechanism exists for this dust.

### Finding Description

**Root Cause — `normalize_amount` uses floor division:** [1](#0-0) 

```rust
/// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
/// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
/// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

**In `sign_transfer`, the normalized (truncated) amount is what gets signed and sent to the destination chain:** [2](#0-1) 

The full `amount` (including dust) was already locked/burned in `init_transfer_internal`: [3](#0-2) 

**When `fee > 0`, dust is recovered:** `claim_fee_callback` computes `fee = transfer_message.amount.0 - denormalized_amount`, which absorbs the dust into the relayer's fee: [4](#0-3) 

**When `fee = 0`, dust is permanently lost:** `sign_transfer_callback` removes the transfer message immediately after signing, with no dust recovery: [5](#0-4) 

After this removal, there is no `claim_fee` call, so the dust (`amount % 10^diff_decimals`) remains locked in the NEAR bridge contract forever (for non-deployed tokens) or is burned (for deployed tokens).

### Impact Explanation

For tokens with large decimal differences (e.g., 24 decimals on NEAR, 6 decimals on EVM), the maximum dust per transfer is `10^18 - 1` units of the NEAR-side token. A user sending `1.999999999999999999` tokens (24 decimals) with `fee = 0` would have only `1` token (6 decimals) arrive at the destination, losing nearly 1 full token worth of dust permanently. This is a direct, permanent loss of bridged user funds — qualifying as escrow mis-accounting and decimal/normalization abuse under the allowed impact scope.

### Likelihood Explanation

The `init_transfer` function is fully public and permissionless. Any user can call `ft_transfer_call` with `fee = 0` and a non-round amount, triggering the dust loss. No special role or privilege is required. The condition is triggered on every transfer where `amount % 10^diff_decimals != 0` and `fee = 0`. [6](#0-5) 

### Recommendation

1. **Enforce minimum fee or round down the transfer amount:** Before locking/burning tokens in `init_transfer_internal`, compute `effective_amount = normalize_amount(amount_without_fee) * 10^diff_decimals` and return the remainder (`dust = amount - effective_amount - fee`) to the sender immediately.
2. **Alternatively, reject zero-fee transfers for tokens with decimal differences:** Require `fee > 0` when `origin_decimals != decimals` to ensure dust is always recoverable via `claim_fee`.

### Proof of Concept

**Setup:** Token with `origin_decimals = 24` on NEAR, `decimals = 6` on EVM. `diff_decimals = 18`.

1. User calls `ft_transfer_call` with `amount = 1_999_999_999_999_999_999_000_000` (≈1.999999 tokens, 24 decimals) and `fee = 0`.
2. `init_transfer_internal` locks the full `1_999_999_999_999_999_999_000_000` units in the NEAR bridge.
3. `sign_transfer` computes: `normalize_amount(1_999_999_999_999_999_999_000_000, {decimals:6, origin_decimals:24})` = `1_999_999_999_999_999_999_000_000 / 10^18` = `1_999_999` (6 decimals = 1.999999 tokens). ✓ passes `> 0` check.
4. The MPC signs a payload for `amount = 1_999_999` (6 decimals).
5. `sign_transfer_callback`: `fee.is_zero()` → `remove_transfer_message(transfer_id)`. Transfer message deleted.
6. EVM contract receives `1_999_999` units (6 decimals).
7. Dust = `1_999_999_999_999_999_999_000_000 - 1_999_999 * 10^18` = `999_000_000_000_000_000` units (24 decimals ≈ 0.000999 tokens) remains permanently locked in the NEAR bridge with no recovery path. [7](#0-6) [5](#0-4) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-480)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1128-1133)
```rust
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-bridge/src/lib.rs (L1829-1857)
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
