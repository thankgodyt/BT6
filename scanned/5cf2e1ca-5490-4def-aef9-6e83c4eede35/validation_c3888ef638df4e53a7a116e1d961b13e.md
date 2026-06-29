### Title
Detached (fire-and-forget) `burn` call in `burn_tokens_if_needed` silently swallows failure, enabling token supply inflation - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`burn_tokens_if_needed` dispatches a cross-contract `burn` call with `.detach()`, discarding the promise result entirely. If the burn fails for any reason, the bridge contract proceeds as though the burn succeeded: the pending transfer is recorded, `InitTransferEvent` is emitted, and a relayer can finalize the transfer on the destination chain — minting tokens there — while the original tokens remain unburned in the bridge's account on the NEAR token contract.

### Finding Description
In `init_transfer_internal`, after recording the pending transfer, the bridge calls `burn_tokens_if_needed`:

```rust
// near/omni-bridge/src/lib.rs  line 1851
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
```

The implementation fires the burn as a detached promise:

```rust
// near/omni-bridge/src/lib.rs  lines 1806-1812
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)   // only 3 TGas
            .burn(amount)
            .detach();                          // result never checked
    }
}
``` [1](#0-0) 

The gas budget for the burn is `BURN_TOKEN_GAS = Gas::from_tgas(3)`: [2](#0-1) 

The `burn` function on the omni-token contract calls `internal_withdraw` on the bridge's own account:

```rust
// near/omni-token/src/lib.rs  lines 146-151
fn burn(&mut self, amount: U128) {
    self.assert_controller();
    self.token
        .internal_withdraw(&env::predecessor_account_id(), amount.into());
}
``` [3](#0-2) 

Because the promise is detached, any failure (gas exhaustion, token contract panic, insufficient balance) is silently swallowed. Execution continues in `init_transfer_internal`: [4](#0-3) 

The same pattern appears in the refund branch of `fin_transfer_send_tokens_callback`, where a failed burn leaves unburned tokens stranded in the bridge's account while the transfer record is removed and lock actions are reverted: [5](#0-4) 

### Impact Explanation
If the burn call fails silently:

- **`init_transfer_internal` path**: The `InitTransferEvent` is emitted and the pending transfer is stored. A relayer finalizes the transfer on the destination chain, minting tokens there. The original tokens are never destroyed and remain in the bridge's account on the NEAR token contract. The result is token supply inflation: the same economic value exists both as unburned tokens in the bridge and as freshly minted tokens on the destination chain.
- **`fin_transfer_send_tokens_callback` refund path**: The transfer record is removed and lock actions are reverted, but the tokens that should have been burned remain in the bridge's account — again inflating the circulating supply.

This constitutes escrow mis-accounting and balance manipulation within the allowed critical impact scope.

### Likelihood Explanation
The gas budget of 3 TGas for `BURN_TOKEN_GAS` is tight. `internal_withdraw` performs a storage read/write on the token contract; under congestion or if the NEAR runtime charges slightly more gas than expected, the call can run out of gas and fail. Additionally, any future change to the omni-token `burn` logic (e.g., adding a storage check or an event log) could push the call over the 3 TGas limit without any change to the bridge contract. Because the failure is silently discarded, there is no on-chain signal that the burn did not occur.

### Recommendation
Replace `.detach()` with a chained callback that checks the burn result and, on failure, either panics (reverting the entire `init_transfer_internal` state change) or explicitly removes the pending transfer and returns the full token amount as a refund. For example:

```rust
ext_token::ext(token)
    .with_static_gas(BURN_TOKEN_GAS)
    .burn(amount)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(BURN_CALLBACK_GAS)
            .burn_callback(transfer_id, storage_owner),
    )
```

Also increase `BURN_TOKEN_GAS` to a safer margin (e.g., 5–10 TGas) to account for future token contract changes.

### Proof of Concept
1. User calls `ft_transfer_call` on an omni-token, transferring `N` tokens to the bridge with a valid `InitTransferMsg`.
2. The bridge's `ft_on_transfer` → `init_transfer_internal` records the pending transfer and fires `burn_tokens_if_needed(...).detach()`.
3. The burn call fails (e.g., gas exhaustion at 3 TGas). The failure is silently ignored.
4. `InitTransferEvent` is emitted with the full transfer details.
5. A relayer submits the proof to the destination chain; the destination bridge mints `N` tokens to the recipient.
6. The bridge's account on the NEAR omni-token contract still holds `N` tokens (never burned).
7. Total circulating supply is now `N` tokens higher than it should be; the bridge's escrow accounting is permanently inconsistent.

### Citations

**File:** near/omni-bridge/src/lib.rs (L72-72)
```rust
const BURN_TOKEN_GAS: Gas = Gas::from_tgas(3);
```

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```

**File:** near/omni-bridge/src/lib.rs (L1806-1812)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
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
```

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```
