### Title
Fee Permanently Locked and Never Paid to Recipient in Fast-Transfer Finalization Path - (File: near/omni-bridge/src/lib.rs)

### Summary
In `process_fin_transfer_to_other_chain`, when a fast transfer is detected, the bridge locks the fee amount for the destination chain but never pays it to any fee recipient and never stores the transfer message that would allow a later `claim_fee` call. The fee is permanently trapped in `locked_tokens`.

### Finding Description
`process_fin_transfer_to_other_chain` handles the case where a foreign-chain → NEAR inbound proof is finalized but the final destination is yet another foreign chain. Before branching on whether a fast transfer pre-existed, the function unconditionally locks the fee for the destination chain:

```rust
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token,
    transfer_message.fee.fee.into(),   // fee locked here
);
```

Then it checks for a fast transfer. In the fast-transfer branch it sends only `amount_without_fee` to the fast-transfer relayer and marks the fast transfer as finalised — but it **does not** store the `TransferMessage` in `pending_transfers` and **does not** pay the fee to anyone:

```rust
if let Some(relayer) = recipient {
    self.send_tokens(token, relayer,
        U128(transfer_message.amount_without_fee()…),  // fee excluded
        "",
    ).detach();
    self.mark_fast_transfer_as_finalised(&fast_transfer.id());
    // ← no add_transfer_message, no fee payment
}
```

The non-fast-transfer branch correctly stores the transfer message so that `claim_fee` can later unlock and pay the fee:

```rust
} else {
    required_balance = self
        .add_transfer_message(transfer_message.clone(), predecessor_account_id.clone())
        …
}
```

`claim_fee_callback` requires `remove_transfer_message` to succeed, which it cannot in the fast-transfer case because the message was never stored. The fee therefore remains locked in `locked_tokens` forever with no code path able to release it.

Contrast this with the analogous "to-NEAR" fast-transfer path (`process_fin_transfer_to_near`, lines 1887–1901), which correctly sets `fee_recipient = status.relayer` and pays the fee through `fin_transfer_send_tokens_callback`. The "to-other-chain" path has no equivalent fee-payment step.

### Impact Explanation
Every fast-transfer finalization for a cross-chain transfer whose final destination is a foreign chain (Ethereum, Solana, Base, etc.) permanently locks the user-specified fee inside the bridge contract. The fee recipient — either the fast-transfer relayer or the finalization relayer — receives nothing. Over time, the `locked_tokens` counter for the destination chain is inflated by the sum of all such lost fees, corrupting the bridge's escrow accounting and making those tokens unrecoverable. This is a direct, permanent loss of bridged funds held in escrow.

### Likelihood Explanation
The fast-transfer-to-other-chain path is a standard, documented bridge operation. Any trusted relayer executing a fast transfer whose recipient is a foreign-chain address will trigger this path on every subsequent finalization. No special conditions or adversarial setup are required; the bug fires on every normal execution of this flow.

### Recommendation
In the fast-transfer branch of `process_fin_transfer_to_other_chain`, pay the fee to the appropriate recipient immediately (mirroring the "to-NEAR" path), or store the transfer message so that `claim_fee` can be called later. The simplest fix is to call `send_fee_internal` (or an equivalent direct token transfer) for `transfer_message.fee.fee` to `predecessor_account_id` before returning, and to call `unlock_tokens_if_needed` for the destination chain to reverse the erroneous lock.

### Proof of Concept

1. User initiates a transfer: origin chain → NEAR → Ethereum, amount = 1000, fee = 10.
2. A fast-transfer relayer calls `ft_transfer_call` with `FastFinTransfer` message, sending 990 tokens (amount minus fee) to the bridge. The bridge records the fast transfer with `relayer = fast_relayer`.
3. A finalization relayer submits the inbound proof via `fin_transfer`, which routes to `process_fin_transfer_to_other_chain`.
4. The function executes:
   - `lock_tokens_if_needed(Eth, token, 10)` — fee locked.
   - Fast transfer detected → sends 990 to `fast_relayer`, marks finalised.
   - Transfer message **not** stored.
5. The 10-token fee is now locked in `locked_tokens[(Eth, token)]` with no stored transfer message.
6. Any attempt to call `claim_fee` with a proof referencing this transfer ID will panic at `remove_transfer_message` because the entry does not exist.
7. The 10 tokens are permanently unrecoverable. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** near/omni-bridge/src/lib.rs (L1887-1901)
```rust
        // If fast transfer happened, change recipient and fee recipient to the relayer that executed fast transfer
        let (recipient, msg, fee_recipient) = match fast_transfer_status {
            Some(status) => {
                require!(
                    !status.finalised,
                    BridgeError::FastTransferAlreadyFinalised.as_ref()
                );
                self.remove_fast_transfer(&fast_transfer.id());
                (status.relayer.clone(), String::new(), status.relayer)
            }
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
```

**File:** near/omni-bridge/src/lib.rs (L1980-2054)
```rust
    fn process_fin_transfer_to_other_chain(
        &mut self,
        predecessor_account_id: AccountId,
        transfer_message: TransferMessage,
    ) {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
        let token = self.get_token_id(&transfer_message.token);

        if transfer_message.recipient.is_utxo_chain() {
            let btc_account_id =
                self.get_utxo_chain_token(transfer_message.get_destination_chain());
            require!(
                token == btc_account_id,
                BridgeError::NativeTokenRequiredForChain.as_ref()
            );
        }

        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );

        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let recipient = if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            require!(
                !status.finalised,
                BridgeError::FastTransferAlreadyFinalised.as_ref()
            );
            Some(status.relayer)
        } else {
            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token,
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            );

            None
        };

        // If fast transfer happened, send tokens to the relayer that executed fast transfer
        if let Some(relayer) = recipient {
            self.send_tokens(
                token,
                relayer,
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
                "",
            )
            .detach();
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
        } else {
            required_balance = self
                .add_transfer_message(transfer_message.clone(), predecessor_account_id.clone())
                .saturating_add(required_balance);
        }

        self.update_storage_balance(
            predecessor_account_id,
            required_balance,
            env::attached_deposit(),
        );

        env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
    }
```

**File:** near/omni-bridge/src/lib.rs (L2650-2702)
```rust
    fn send_fee_internal(
        &mut self,
        transfer_message: &TransferMessage,
        fee_recipient: AccountId,
        token_fee: u128,
    ) -> PromiseOrValue<()> {
        if transfer_message.fee.native_fee.0 != 0 {
            let origin_chain = transfer_message.origin_transfer_id.as_ref().map_or_else(
                || transfer_message.get_origin_chain(),
                |origin_transfer_id| origin_transfer_id.origin_chain,
            );

            if origin_chain.is_utxo_chain() {
                env::panic_str(BridgeError::NativeFeeForUtxoChain.to_string().as_str())
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        env::log_str(
            &OmniBridgeEvent::ClaimFeeEvent {
                transfer_message: transfer_message.clone(),
            }
            .to_log_string(),
        );

        self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);

        if token_fee > 0 {
            if self.is_deployed_token(&token) {
                ext_token::ext(token)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient, U128(token_fee), None)
                    .into()
            } else {
                ext_token::ext(token)
                    .with_static_gas(FT_TRANSFER_GAS)
                    .with_attached_deposit(ONE_YOCTO)
                    .ft_transfer(fee_recipient, U128(token_fee), None)
                    .into()
            }
        } else {
            PromiseOrValue::Value(())
        }
    }
```
