### Title
Insufficient `fee` Validation in `init_transfer` Causes Permanent Token Lock When Normalized Amount Rounds to Zero - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `init_transfer` function in the NEAR omni-bridge contract only validates `fee < amount`, but does not verify that the remaining amount after fee deduction (`amount - fee`) is sufficient to produce a non-zero value after decimal normalization to the destination chain. Tokens are locked on NEAR immediately, but the downstream `sign_transfer` call will always revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because the fee can only be increased (never decreased) and no cancel/refund path exists, the user's tokens are permanently frozen in the bridge.

### Finding Description

The `init_transfer` function validates the fee with a single check:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

This check only ensures `fee < amount`, but does not ensure that `amount - fee` is large enough to survive decimal normalization. The `normalize_amount` function uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [2](#0-1) 

For tokens with a large decimal difference (e.g., 24 NEAR decimals → 6 destination decimals, `diff = 18`), the minimum transferable unit is `10^18` NEAR-side tokens. If a user sets `fee = amount - X` where `X < 10^18`, then `normalize_amount(X, decimals) = 0`.

The `sign_transfer` function does check for this condition:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [3](#0-2) 

However, this check occurs **after** the tokens are already locked in the bridge. The `sign_transfer` call will always revert, and the transfer message remains in storage indefinitely.

The `update_transfer_fee` function enforces that the new fee must be **greater than or equal to** the current fee, making it impossible to lower the fee to recover the transfer:

```rust
require!(
    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [4](#0-3) 

There is no cancel or refund mechanism for pending transfers, so the locked tokens cannot be recovered.

### Impact Explanation

A user who sets a `fee` value that leaves `amount - fee < 10^(origin_decimals - dest_decimals)` will have their tokens permanently locked in the NEAR bridge contract. The source-chain lock succeeds, but the transfer can never be finalized on the destination chain. This constitutes a permanent freezing of bridged funds, matching the Critical impact scope.

### Likelihood Explanation

This is realistic for tokens with large decimal differences (e.g., 24 NEAR decimals to 6 EVM decimals). A user offering a fee of "almost 1 destination unit" in NEAR-side units may inadvertently leave a sub-unit remainder that normalizes to zero. The condition is reachable by any unprivileged user via the public `ft_transfer_call` → `init_transfer` path with no special privileges required.

### Recommendation

Add a validation in `init_transfer` (after decimal information is available) to ensure `normalize_amount(amount - fee, decimals) > 0`. If decimals are not available at `init_transfer` time, add a minimum transferable amount check based on the registered token decimals, or reject the transfer at `init_transfer` time with the same guard already present in `sign_transfer`.

### Proof of Concept

Consider a token registered with `origin_decimals = 24`, `decimals = 6` (diff = 18):

1. User calls `ft_transfer_call` with `amount = 2_000_000_000_000_000_000` (2 × 10^18).
2. User sets `fee = 1_000_000_000_000_000_001` (just over 10^18), which satisfies `fee < amount`.
3. `init_transfer` passes the `fee < amount` check and locks the tokens.
4. `amount_without_fee = 999_999_999_999_999_999` (just under 10^18).
5. Relayer calls `sign_transfer`; `normalize_amount(999_999_999_999_999_999, diff=18) = 0`.
6. `require!(0 > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Transfer message remains in storage; tokens remain locked.
8. `update_transfer_fee` cannot lower the fee (only increase allowed).
9. Tokens are permanently frozen with no recovery path. [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L386-436)
```rust
    #[payable]
    #[pause]
    pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
        match fee {
            UpdateFee::Fee(fee) => {
                let mut transfer = self.get_transfer_message_storage(transfer_id);

                require!(
                    transfer.message.origin_transfer_id.is_none(),
                    BridgeError::UpdateFeeNotAllowedForTransfer.as_ref()
                );

                let current_fee = transfer.message.fee;
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );

                require!(
                    fee.fee == current_fee.fee
                        || OmniAddress::Near(env::predecessor_account_id())
                            == transfer.message.sender,
                    BridgeError::SenderCanUpdateTokenFeeOnly.as_ref()
                );

                let diff_native_fee = fee
                    .native_fee
                    .0
                    .checked_sub(current_fee.native_fee.0)
                    .near_expect(BridgeError::LowerFee);

                require!(
                    NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
                    BridgeError::InvalidAttachedDeposit.as_ref()
                );

                transfer.message.fee = fee;
                self.insert_raw_transfer(transfer.message.clone(), transfer.owner);

                env::log_str(
                    &OmniBridgeEvent::UpdateFeeEvent {
                        transfer_message: transfer.message,
                    }
                    .to_log_string(),
                );
            }
            UpdateFee::Proof(_) => {
                env::panic_str(BridgeError::UnsupportedFeeUpdateProof.to_string().as_str())
            }
        }
    }
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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
