### Title
Dust Transfer Permanently Freezes User Funds Due to Missing Pre-Normalization Validation — (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` locks/burns user tokens on NEAR before validating that the transferred amount, after decimal normalization, is non-zero on the destination chain. When a user sends a dust amount that normalizes to zero, their tokens are permanently frozen: `sign_transfer` will always revert with `InvalidAmountToTransfer`, and no recovery path exists.

### Finding Description

The bridge stores token decimal metadata as a `Decimals` struct with two fields: `origin_decimals` (NEAR-side precision) and `decimals` (destination-chain precision). When bridging outbound, `normalize_amount` divides by `10^(origin_decimals - decimals)` using floor division. [1](#0-0) 

For a NEAR token with 24 decimals bridging to a 6-decimal destination (e.g., USDC on EVM), the normalization factor is `10^18`. Any amount below `10^18` units normalizes to zero.

The `init_transfer` entry point (reached via `ft_on_transfer`) only validates `fee < amount`. It does **not** look up the token's `Decimals` or verify that `normalize_amount(amount - fee, decimals) > 0`. [2](#0-1) 

Execution then proceeds to `init_transfer_internal`, which burns or locks the full token amount and stores the transfer in `pending_transfers`, returning `U128(0)` to the NEP-141 callback (keeping the tokens). [3](#0-2) 

Later, when a relayer calls `sign_transfer`, the normalization check fires: [4](#0-3) 

This `require!` panics the entire transaction. Because the panic occurs before the MPC call, `sign_transfer_callback` is never reached, so the transfer is never removed from `pending_transfers`. The transfer is permanently stuck, and the tokens are permanently lost.

`update_transfer_fee` cannot rescue the transfer: it requires `fee < amount`, so the maximum achievable `amount_without_fee` is `1`, which still normalizes to zero when the decimal gap is large. [5](#0-4) 

### Impact Explanation

User tokens are permanently frozen in the bridge. The `pending_transfers` entry can never be finalized (sign always fails) and there is no cancel/refund function. This constitutes **permanent freezing of bridged funds**, which is in the critical impact scope.

### Likelihood Explanation

The scenario is realistic for any NEAR-native token with 24 decimals bridging to a 6-decimal destination (normalization factor `10^18`). A user sending fewer than `10^18` base units (e.g., less than `1` full token for a 24-decimal token) triggers the bug. Users unfamiliar with decimal precision differences can easily hit this. No special privileges or frontrunning are required — the user triggers it themselves via the public `ft_transfer_call` → `ft_on_transfer` path.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before burning/locking tokens. Look up the destination token's `Decimals` and assert:

```rust
let token_address = self.get_token_address(destination_chain, token_id);
if let Some(decimals) = token_address.and_then(|a| self.token_decimals.get(&a)) {
    let normalized = Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals,
    );
    require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
}
```

This mirrors the guard already present in `sign_transfer` but moves it to the point before funds are committed.

### Proof of Concept

1. A NEAR token `token.near` has `origin_decimals = 24`, `decimals = 6` on Ethereum (normalization factor = `10^18`).
2. User calls `ft_transfer_call` on `token.near` with `amount = 500_000_000_000_000_000` (0.5 tokens, below `10^18`), targeting the bridge with an `InitTransfer` message to an Ethereum recipient.
3. `init_transfer` passes the `fee < amount` check. `init_transfer_internal` burns the 0.5 tokens and stores the transfer in `pending_transfers`. `ft_on_transfer` returns `U128(0)` — tokens are gone.
4. Relayer calls `sign_transfer` for this transfer. `normalize_amount(500_000_000_000_000_000, Decimals { origin_decimals: 24, decimals: 6 })` = `500_000_000_000_000_000 / 10^18` = `0`. The `require!(amount_to_transfer > 0)` panics.
5. The transfer remains in `pending_transfers` indefinitely. The 0.5 tokens are permanently burned with no recovery path. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-401)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
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
