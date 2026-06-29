### Title
Missing Pre-Lock Minimum-Amount Validation Causes Permanent Token Freeze — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`init_transfer` locks or burns user tokens before any check that the normalized destination-chain amount is non-zero. The only guard against a zero normalized amount lives in `sign_transfer`, which is called later by a relayer. When the guard fires there, the tokens are already irrecoverably locked/burned and no cancel path exists.

---

### Finding Description

`normalize_amount` uses integer floor division to convert a NEAR-side token amount to the destination-chain precision: [1](#0-0) 

For any token whose NEAR decimals exceed its destination-chain decimals (e.g. a token with 24 NEAR decimals bridging to an EVM chain with 6 decimals, giving a divisor of `10^18`), any transfer amount below the divisor normalizes to zero.

`init_transfer` only validates `fee < amount`: [2](#0-1) 

`init_transfer_internal` then immediately locks or burns the full amount: [3](#0-2) 

The zero-amount guard appears only in `sign_transfer`, which executes after the lock/burn: [4](#0-3) 

When `sign_transfer` panics with `InvalidAmountToTransfer`, the transfer message remains in `pending_transfers` but the tokens are already gone. There is no public cancel or refund function; `remove_transfer_message` is internal-only and does not unlock or un-burn tokens: [5](#0-4) 

The only privileged escape valve is `set_locked_tokens` (DAO/TokenLockController role), which adjusts accounting but does not return tokens to users: [6](#0-5) 

---

### Impact Explanation

Any user who initiates a NEAR→EVM (or NEAR→other-chain) transfer with `amount - fee < 10^(origin_decimals − decimals)` permanently loses their tokens. For a token with 24 NEAR decimals and 6 EVM decimals the threshold is one full token unit (10^18 base units). This constitutes **permanent freezing of bridged funds**, which is in the critical allowed-impact scope.

---

### Likelihood Explanation

The scenario arises organically: a user who misestimates the decimal gap, or who sends a "dust" cleanup transfer, will trigger it without any malicious intent. The `ft_transfer_call` entry point is fully public and requires no special role. The decimal difference is a fixed protocol parameter visible on-chain, so a determined actor can also craft the exact amount deliberately.

---

### Recommendation

Add the normalization check **before** locking or burning tokens, either inside `init_transfer` (after the fee check) or at the top of `init_transfer_internal`:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(decimals) = token_address.and_then(|a| self.token_decimals.get(&a)) {
    let normalized = Self::normalize_amount(
        transfer_message.amount_without_fee().expect("fee < amount"),
        decimals,
    );
    require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
}
```

This mirrors the existing guard in `sign_transfer` but fires before any state mutation.

---

### Proof of Concept

1. Register a token whose NEAR-side `origin_decimals = 24` and EVM-side `decimals = 6` (divisor = `10^18`).
2. Call `ft_transfer_call` on the NEP-141 token with `amount = 999_999_999_999_999_999` (just below `10^18`) and a valid EVM recipient. `init_transfer` accepts the call (`fee=0 < amount`), locks the tokens, and emits `InitTransferEvent`.
3. A relayer calls `sign_transfer` for the resulting transfer ID. `normalize_amount(999_999_999_999_999_999) = 0`; the call panics with `InvalidAmountToTransfer`.
4. The transfer message stays in `pending_transfers`; the tokens remain locked with no recovery path. The user has permanently lost their funds. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** near/omni-bridge/src/token_lock.rs (L38-44)
```rust
    #[access_control_any(roles(Role::DAO, Role::TokenLockController))]
    pub fn set_locked_tokens(&mut self, args: Vec<SetLockedTokenArgs>) {
        for arg in args {
            self.locked_tokens
                .insert(&(arg.chain_kind, arg.token_id), &arg.amount.0);
        }
    }
```
