### Title
Decimal Normalization Truncation Permanently Locks User Funds When Transfer Amount Normalizes to Zero - (`near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates a NEAR→external-chain transfer, the bridge first locks/burns the user's tokens in `init_transfer_internal`, then later a relayer calls `sign_transfer` which applies `normalize_amount` (floor division) to scale the amount to the destination chain's decimal precision. If the user's `amount_without_fee` is smaller than `10^(origin_decimals - decimals)`, the normalized result is 0. `sign_transfer` then panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`, but the tokens were already irreversibly burned/locked in the prior transaction. No cancel or refund path exists, so the user's funds are permanently lost.

### Finding Description

The bridge stores a `Decimals` struct per token address containing `origin_decimals` (NEAR-side precision) and `decimals` (destination-chain precision).

`normalize_amount` performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

In `sign_transfer`, this is applied to `amount_without_fee` and guarded:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
``` [2](#0-1) 

The guard fires **after** the user's tokens have already been burned or locked in `init_transfer_internal` (a separate, earlier transaction):

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [3](#0-2) 

The transfer message can only be removed via `sign_transfer_callback` (when fee is zero and signing succeeds) or `claim_fee_callback` (after destination-chain finalization). Neither path is reachable when `sign_transfer` panics before reaching the MPC call. [4](#0-3) 

There is no user-callable cancel or refund function. The pending transfer entry persists in `pending_transfers` indefinitely while the underlying tokens are gone.

The code comment acknowledges dust truncation but only for the remainder case, not the total-truncation-to-zero case:

```
/// When fee = 0, dust stays locked/burned.
``` [5](#0-4) 

The `CLAUDE.md` false-positive note for "Decimal Arithmetic Underflow" covers only the `origin_decimals < decimals` underflow/panic case, not the scenario where a valid `origin_decimals > decimals` configuration causes the entire amount to truncate to zero. [6](#0-5) 

### Impact Explanation

A user who transfers an amount smaller than `10^(origin_decimals - decimals)` in the token's smallest unit permanently loses those tokens. The tokens are burned (for deployed/bridged tokens) or locked (for native tokens) with no recovery path. Concrete examples:

- **NEAR-native token (24 decimals) → Solana (9 decimals):** any transfer below `10^15` yoctoNEAR (= 0.001 NEAR) is permanently lost.
- **BTC-like token (8 decimals) → 6-decimal destination:** any transfer below 100 satoshis (≈ $0.06 at $60k BTC) is permanently lost.

The loss per transfer is bounded by `10^(origin_decimals - decimals) - 1` in the origin token's smallest unit, but it is a **permanent, unrecoverable** loss of bridged funds — fitting the "escrow mis-accounting / decimal normalization abuse that changes user balances" impact category.

### Likelihood Explanation

Any user who initiates a transfer with an amount below the normalization threshold triggers this. The threshold is determined by the registered `Decimals` configuration, which is set at token deployment time and is not visible to ordinary users. A user bridging a small "test" amount or a dust amount from a prior operation can unknowingly hit this condition. No attacker action is required; the user's own `ft_transfer_call` is the entry point.

### Recommendation

Add a pre-flight normalization check inside `init_transfer` (before burning/locking tokens) to reject transfers whose `amount_without_fee` would normalize to zero on the destination chain:

```rust
// In init_transfer, after constructing transfer_message:
if let Some(token_address) = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This ensures the rejection happens before any token state change, allowing the `ft_transfer_call` to refund the user automatically.

### Proof of Concept

1. Register a token with `origin_decimals = 8`, `decimals = 6` (e.g., a BTC-like token bridged to a 6-decimal EVM representation).
2. User calls `ft_transfer_call` with `amount = 50` (50 satoshis) and `fee = 0`.
3. Bridge's `ft_on_transfer` → `init_transfer` → `init_transfer_internal`: 50 satoshis are burned/locked; transfer message stored.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(50, Decimals { decimals: 6, origin_decimals: 8 })` = `50 / 100` = **0**.
6. `require!(amount_to_transfer > 0)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Transfer message remains in `pending_transfers`; 50 satoshis are permanently lost. [1](#0-0) [2](#0-1) [7](#0-6)

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

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
