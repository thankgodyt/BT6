### Title
Decimal Normalization in `sign_transfer` Can Permanently Lock User Funds for Sub-Threshold Transfers — (File: `near/omni-bridge/src/lib.rs`)

### Summary
When a user initiates a NEAR → EVM transfer with an amount (after fee) smaller than `10^(origin_decimals − decimals)`, the tokens are immediately locked or burned by `init_transfer`, but the transfer can never be completed. `sign_transfer` applies `normalize_amount` (floor division) to the net amount, producing zero, and then panics on the `require!(amount_to_transfer > 0)` guard. No on-chain cancellation path exists, so the user's funds are permanently frozen in `pending_transfers`.

### Finding Description

**Step 1 — Tokens locked with no pre-validation of normalizability.**

`init_transfer` stores the `TransferMessage` and immediately locks (or burns, for deployed tokens) the full user amount without checking whether the net amount survives the later normalization step. [1](#0-0) 

**Step 2 — `normalize_amount` uses floor division.**

```
normalize_amount(amount, decimals) = amount / 10^(origin_decimals − decimals)
```

For a NEAR token with 24 decimals bridged to an EVM chain where it is represented with 6 decimals, `diff_decimals = 18`. Any net amount below `10^18` units rounds to zero. [2](#0-1) 

**Step 3 — `sign_transfer` panics after tokens are already locked.**

`sign_transfer` calls `normalize_amount` on `amount_without_fee()` and then asserts the result is positive. Because the panic occurs *before* the MPC async call, `sign_transfer_callback` is never reached. [3](#0-2) 

**Step 4 — No cancellation path exists.**

`remove_transfer_message` is only reachable via `sign_transfer_callback` (when `fee.is_zero()`) or `claim_fee_callback`. Neither is reachable when `sign_transfer` panics. `remove_transfer_message_without_refund` is only called inside `init_transfer_internal` on storage-balance failure, before tokens are locked. [4](#0-3) 

The design comment acknowledges dust locking only for the *remainder* of floor division, not for the case where the entire net amount is below the divisor: [5](#0-4) 

The CLAUDE.md false-positive note covers only the *underflow panic* (`origin_decimals < decimals`), not the silent zero-result case described here. [6](#0-5) 

### Impact Explanation
A user's tokens are permanently frozen in `pending_transfers` with no on-chain recovery mechanism. For deployed (bridged) tokens, `burn_tokens_if_needed` is called at lock time, making the loss irreversible even at the token-supply level. [1](#0-0) 

This satisfies the allowed impact: **permanent freezing of bridged funds**.

### Likelihood Explanation
The threshold for the bug to trigger is `amount_without_fee < 10^diff_decimals`. For a 24-decimal NEAR token bridged to a 6-decimal EVM representation, the threshold is `10^18` base units (= 0.000001 of the token). Any user who sends a transfer below this threshold — whether by accident or due to a UI rounding error — will have their funds permanently locked. The bridge imposes no minimum-amount guard at `init_transfer` time, so the condition is fully user-reachable without any privileged action. [7](#0-6) 

### Recommendation
Add a normalizability check inside `init_transfer` (before locking tokens) that mirrors the check already present in `sign_transfer`:

```rust
// In init_transfer, after building transfer_message and before init_transfer_internal:
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(token_address) = token_address {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let net = transfer_message.amount_without_fee()
            .expect("fee < amount already checked");
        require!(
            Self::normalize_amount(net, decimals) > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
    }
}
```

Alternatively, add a DAO-callable rescue function that can remove a stuck `pending_transfer` and refund the storage owner.

### Proof of Concept

1. A NEAR-native token has `origin_decimals = 24` on NEAR and `decimals = 6` on the EVM destination (`diff_decimals = 18`).
2. User calls `ft_transfer_call` with `amount = 5 × 10^17` (0.0000005 of the token) and `fee = 0`.
3. `init_transfer` passes the `fee < amount` guard, stores the `TransferMessage`, and locks `5 × 10^17` units.
4. Trusted relayer calls `sign_transfer`.
5. `normalize_amount(5 × 10^17, Decimals { decimals: 6, origin_decimals: 24 })` = `5 × 10^17 / 10^18` = **0**.
6. `require!(amount_to_transfer > 0, ...)` **panics**; the transaction reverts.
7. The `TransferMessage` remains in `pending_transfers`; `sign_transfer_callback` is never called.
8. The user's `5 × 10^17` units are permanently locked with no on-chain recovery path. [3](#0-2) [2](#0-1) [8](#0-7)

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
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

**File:** near/CLAUDE.md (L192-196)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption

```
