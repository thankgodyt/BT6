### Title
Fee Tokens Permanently Lost When Fee Recipient Is Not Registered in Token Contract — (File: `near/omni-bridge/src/lib.rs`)

### Summary
In `claim_fee_callback`, the transfer message is irrevocably removed and `locked_tokens` is decremented before the cross-contract fee transfer executes. Because NEAR cross-contract calls run in separate receipts, if the fee recipient (relayer) is not registered in the token contract, the `ft_transfer` panics in its own receipt while the state mutations in `claim_fee_callback` are already committed. The fee tokens are permanently frozen in the bridge's account with no recovery path.

### Finding Description

`claim_fee_callback` executes the following sequence synchronously in one receipt:

1. Validates the proof and fee recipient identity
2. Calls `self.remove_transfer_message(fin_transfer.transfer_id)` — permanently deletes the pending transfer record
3. Calls `self.send_fee_internal(...)` which calls `self.unlock_tokens_if_needed(...)` — decrements `locked_tokens`
4. Returns a `PromiseOrValue` wrapping the `ft_transfer` (or `mint`) cross-contract call [1](#0-0) 

Inside `send_fee_internal`, for non-deployed tokens the fee is sent via:

```rust
ext_token::ext(token)
    .with_static_gas(FT_TRANSFER_GAS)
    .with_attached_deposit(ONE_YOCTO)
    .ft_transfer(fee_recipient, U128(token_

### Citations

**File:** near/omni-bridge/src/lib.rs (L1094-1133)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);

        if let Some(origin_transfer_id) = transfer_message.origin_transfer_id.clone() {
            let mut fast_transfer = FastTransfer::from_transfer(
                transfer_message.clone(),
                self.get_token_id(&transfer_message.token),
            );
            fast_transfer.transfer_id = origin_transfer_id;

            if let Some(fast_transfer_status) = self.get_fast_transfer_status(&fast_transfer.id()) {
                // For fast transfers we need to wait for finalization of the first leg (Origin chain -> Near) before allowing fee claim.
                // This confirms that fast transfer was executed with correct parameters.
                // Othewise malicious relayer can create a fast transfer with arbitrary high fee and claim it here.
                if fast_transfer_status.finalised {
                    self.remove_fast_transfer(&fast_transfer.id());
                } else {
                    env::panic_str(BridgeError::FastTransferNotFinalised.to_string().as_str());
                }
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        let token_address = self
            .get_token_address(transfer_message.get_destination_chain(), token.clone())
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```
