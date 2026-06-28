### Title
No Minimum Transfer Amount Allows Permanent Freezing of Bridged Funds via Zero-Normalized Transfer - (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` on NEAR accepts any `amount` where `fee < amount`, without verifying that `normalize_amount(amount - fee, decimals) > 0`. For tokens whose NEAR-side decimals exceed the destination-chain decimals, a user can initiate a transfer whose net amount truncates to zero after normalization. The transfer is then permanently stuck: `sign_transfer` rejects it with `InvalidAmountToTransfer`, but the tokens are already locked or burned with no cancel/refund path.

### Finding Description

`init_transfer` enforces only one size constraint: [1](#0-0) 

This allows `amount - fee` to be any positive value, including values smaller than the normalization unit `10^(origin_decimals - decimals)`.

`normalize_amount` uses floor division: [2](#0-1) 

When `amount - fee < 10^(origin_decimals - decimals)`, the result is `0`. The relayer then calls `sign_transfer`, which catches this: [3](#0-2) 

But by this point `init_transfer_internal` has already executed, locking or burning the tokens: [4](#0-3) 

The transfer record remains in `pending_transfers` indefinitely. No cancel or refund entry point exists in the contract.

### Impact Explanation

Bridged funds are permanently frozen. The user's tokens are locked on NEAR (or burned for deployed tokens), the destination chain never receives anything, and no recovery path exists. This satisfies the allowed impact: *permanent freezing of bridged funds*.

For tokens with large decimal differences — e.g., a token registered with `origin_decimals = 24` and `decimals = 6` — the normalization unit is `10^18`. Any transfer where `amount - fee < 10^18` base units triggers the freeze. The comment in the code acknowledges the dust-locking behavior but only for the remainder case, not the total-amount-zero case: [5](#0-4) 

### Likelihood Explanation

Any unprivileged user calling `ft_on_transfer` → `init_transfer` with a small amount can trigger this. The EVM and Solana `initTransfer` entry points also accept arbitrary amounts with only `fee < amount` checked: [6](#0-5) [7](#0-6) 

For tokens with large decimal gaps (e.g., 24 vs 6), the threshold is `10^18` base units — a non-trivial amount that a user could accidentally send. The attacker-controlled entry path is fully permissionless.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before locking/burning tokens:

```rust
let token_address = self.get_token_address(destination_chain, &token_id)
    .near_expect(BridgeError::TokenNotFound);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the existing guard in `sign_transfer` but enforces it before funds are committed.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 6` (normalization unit = `10^18`).
2. User calls `ft_on_transfer` transferring `amount = 10^18 - 1` with `fee = 0`.
3. `init_transfer` passes: `fee (0) < amount (10^18 - 1)`. Tokens are locked via `init_transfer_internal`.
4. Relayer calls `sign_transfer`. `normalize_amount(10^18 - 1, {24, 6}) = 0`. Contract panics with `InvalidAmountToTransfer`.
5. Transfer remains in `pending_transfers`. Tokens are permanently locked. No cancel function exists. [8](#0-7) [9](#0-8)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L382-384)
```text
        if (fee >= amount) {
            revert InvalidFee();
        }
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L73-73)
```rust
        require!(payload.amount > payload.fee, ErrorCode::InvalidFee);
```
