### Title
User Tokens Permanently Locked When Transfer Amount Normalizes to Zero — (`near/omni-bridge/src/lib.rs`)

### Summary
The NEAR `omni-bridge` contract locks or burns a user's tokens during `init_transfer` without first verifying that the transfer amount, after decimal normalization, is greater than zero. The zero-amount guard only exists in `sign_transfer`, which is called later by a relayer. Because there is no cancel or withdrawal mechanism for pending transfers, any transfer whose normalized amount is zero results in permanent, irrecoverable loss of the user's bridged tokens.

### Finding Description

**Root cause — missing pre-lock validation in `init_transfer_internal`:**

When a user calls `ft_transfer_call` on a NEP-141 token, the bridge's `ft_on_transfer` handler eventually calls `init_transfer_internal`. Inside that function, tokens are locked (or burned for deployed bridge tokens) unconditionally:

```rust
// near/omni-bridge/src/lib.rs  ~line 1850
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
```

No check is performed here that `normalize_amount(amount_without_fee) > 0`.

**The guard that should protect users only fires later, in `sign_transfer`:**

```rust
// near/omni-bridge/src/lib.rs  ~line 475
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

`normalize_amount` performs floor division by `10^(origin_decimals − decimals)`:

```rust
// near/omni-bridge/src/lib.rs  ~line 2784
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token registered with `origin_decimals = 24` and `decimals = 6` (a common pairing for NEAR-native tokens bridged to EVM), the divisor is `10^18`. Any transfer amount below `10^18` yoctoNEAR (i.e., below 1 NEAR) normalizes to zero.

**No recovery path exists:**

`sign_transfer` panics before it ever calls the MPC signer, so `sign_transfer_callback` is never reached and the transfer record is never removed. The only places `remove_transfer_message` is called are inside `claim_fee_callback` (requires a successful finalization proof from the destination chain) and `sign_transfer_callback` (never reached). There is no public `cancel_transfer` or user-accessible withdrawal function.

The `ft_on_transfer` return value of `U128(0)` (tokens consumed, not refunded) is committed as soon as `init_transfer_internal` succeeds, so the NEP-141 token contract does not refund the user.

### Impact Explanation
A user who sends a sub-threshold amount (e.g., any amount < 1 NEAR for a 24→6 decimal token) has their tokens permanently locked inside the bridge contract. The transfer record sits in `pending_transfers` indefinitely; no relayer can ever sign it, and no on-chain path exists to return the tokens to the user. This constitutes a permanent, irrecoverable loss of bridged funds.

### Likelihood Explanation
The decimal gap between NEAR (24 decimals) and EVM (commonly 6 or 8 decimals) is large and well-known. A user sending "dust" amounts, testing the bridge with a small value, or miscalculating units can trivially trigger this. The entry path is the standard, publicly documented `ft_transfer_call` flow — no special role or privilege is required.

### Recommendation
Add a normalization check inside `init_transfer` (before tokens are locked/burned) that rejects the transfer if the normalized amount would be zero:

```rust
// Proposed guard in init_transfer, after building transfer_message
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(addr) = token_address {
    if let Some(decimals) = self.token_decimals.get(&addr) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

Alternatively, add a `cancel_transfer` function that allows the original sender to reclaim tokens from a transfer that has never been signed.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 6` (NEAR → EVM, standard configuration).
2. Call `ft_transfer_call` with `amount = 999_999_999_999_999_999` (< 1 NEAR = `10^18` yoctoNEAR), `msg = InitTransferMsg { fee: U128(0), native_token_fee: U128(0), recipient: <eth_address>, ... }`.
3. `init_transfer_internal` succeeds: tokens are locked, transfer stored in `pending_transfers`, `ft_on_transfer` returns `U128(0)` (tokens consumed).
4. Relayer calls `sign_transfer` for the new `TransferId`.
5. `normalize_amount(999_999_999_999_999_999, Decimals { decimals: 6, origin_decimals: 24 })` = `999_999_999_999_999_999 / 10^18` = `0`.
6. `require!(0 > 0, ...)` panics — transaction reverts, transfer record untouched.
7. No further call can ever complete or cancel this transfer; the user's tokens are permanently locked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L648-667)
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
