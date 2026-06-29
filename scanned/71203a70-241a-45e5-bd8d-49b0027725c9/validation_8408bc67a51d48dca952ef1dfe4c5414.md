### Title
Permanent Freezing of User Funds When Normalized Transfer Amount Is Zero — (`near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates an outbound transfer (NEAR → foreign chain) with an amount that is too small to survive decimal normalization, the tokens are irreversibly burned or locked during `init_transfer_internal`, but `sign_transfer` will always panic with `InvalidAmountToTransfer`. No cancel or refund path exists, permanently freezing the user's funds.

### Finding Description

The outbound transfer flow has a critical ordering flaw:

**Step 1 — Tokens are burned/locked unconditionally in `init_transfer_internal`:** [1](#0-0) 

Deployed tokens are burned via `burn_tokens_if_needed`; native tokens are locked via `lock_tokens_if_needed`. Both happen before any check that the amount is large enough to be transferred to the destination chain.

**Step 2 — `sign_transfer` normalizes the amount and panics if it rounds to zero:** [2](#0-1) 

`normalize_amount` uses floor division: [3](#0-2) 

For a token with `origin_decimals=24` and `decimals=18`, the divisor is `10^6`. Any transfer amount below `10^6` normalizes to `0`, causing `sign_transfer` to always panic. The panic reverts the `sign_transfer` call but does **not** undo the already-committed burn/lock from Step 1.

**Step 3 — `sign_transfer_callback` has no recovery path on failure:** [4](#0-3) 

When MPC signing fails (or `sign_transfer` panics before even reaching MPC), the callback does nothing — no refund, no cleanup. The transfer message stays in `pending_transfers` indefinitely.

**No cancel/refund function exists.** The only ways `remove_transfer_message` is called are on successful `sign_transfer` with zero fee, and on successful `claim_fee_callback`. Neither is reachable when the amount normalizes to zero. [5](#0-4) 

The SECURITY.md documents that "dust stays locked/burned" when `fee=0`, but this refers to the sub-unit remainder after normalization of a large amount — not the case where the **entire** amount is below the normalization threshold and nothing can ever be transferred.

### Impact Explanation

For deployed (bridged) tokens: the tokens are burned and permanently destroyed — there is no mint-back path. For native tokens: the tokens are locked in the bridge contract with no unlock path available to the user. In both cases the funds are permanently frozen. The amount frozen per incident is bounded by the normalization threshold (e.g., up to `10^6 - 1` base units for a 6-decimal-difference token), but there is no floor on how many users can be affected.

### Likelihood Explanation

Any user who sends a transfer amount smaller than `10^(origin_decimals - decimals)` triggers this. For tokens with a 6-decimal gap (common for NEAR-native tokens bridged to EVM), the threshold is 1 USDC-equivalent unit. A user who accidentally enters a small amount, or whose amount is reduced by a fee to below the threshold, will lose their funds silently — `init_transfer` accepts the call without error.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) **before** burning or locking tokens:

```rust
let token_address = self.get_token_address(destination_chain, token_id.clone());
if let Some(addr) = token_address {
    if let Some(decimals) = self.token_decimals.get(&addr) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee()?,
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This mirrors the guard already present in `sign_transfer` but places it before any irreversible state change.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (normalization divisor = `10^6`).
2. User calls `ft_transfer_call` transferring `500_000` base units with `fee = 0`.
3. `init_transfer` passes the only guard (`fee < amount` → `0 < 500_000` ✓).
4. `init_transfer_internal` burns the `500_000` tokens (deployed token) and stores the transfer message.
5. Trusted relayer calls `sign_transfer`. `normalize_amount(500_000, {24,18})` = `500_000 / 10^6` = `0`. The `require!(amount_to_transfer > 0)` panics.
6. The panic reverts `sign_transfer` but the burn from Step 4 is already committed on-chain.
7. Every subsequent `sign_transfer` call for this transfer ID panics identically.
8. No cancel or refund function exists. The `500_000` tokens are permanently destroyed.

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

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
