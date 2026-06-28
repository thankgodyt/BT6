### Title
Missing Minimum Amount Validation After Decimal Normalization in `init_transfer` Leads to Permanent Fund Freezing - (File: near/omni-bridge/src/lib.rs)

### Summary

The `init_transfer` function in the NEAR omni-bridge contract locks/burns user tokens and stores a pending transfer without validating that the transferred amount will produce a non-zero value after decimal normalization to the destination chain's precision. The zero-amount guard only exists in `sign_transfer`, which is called after the tokens are already irrecoverably locked or burned. This is the direct analog of the GDACurve bug: a computed value (normalized transfer amount) is not validated against a minimum bound at the point of state change, only at a later, separate call.

---

### Finding Description

The bridge stores token decimals in two fields: `origin_decimals` (the token's native precision on the source chain) and `decimals` (the capped precision used on NEAR). When a NEAR-originated transfer is signed for delivery to a foreign chain, `normalize_amount` divides the NEAR-side amount by `10^(origin_decimals - decimals)`: [1](#0-0) 

The zero-amount guard is placed exclusively inside `sign_transfer`: [2](#0-1) 

However, `init_transfer` — which is the function that actually locks or burns the user's tokens — only checks that `fee < amount`: [3](#0-2) 

It does **not** check that `normalize_amount(amount - fee, decimals) > 0`. The tokens are committed (locked or burned) inside `init_transfer_internal` before any normalization check ever runs: [4](#0-3) 

The transfer message is then stored in `pending_transfers`. When the relayer subsequently calls `sign_transfer`, normalization is applied and the `> 0` guard fires — but at that point the tokens are already gone and the transfer record is permanently stuck.

---

### Impact Explanation

Any user who initiates a NEAR → Foreign transfer with an amount smaller than `10^(origin_decimals - decimals)` will have their tokens permanently frozen. For example, for a token configured with `origin_decimals = 24` and `decimals = 18` (a 6-decimal difference), any transfer amount below `1_000_000` (10^6 base units) normalizes to zero. The transfer record cannot be completed (every `sign_transfer` call reverts with `ERR_INVALID_AMOUNT_TO_TRANSFER`) and no cancel/refund path was found in the contract. The impact maps directly to the allowed scope: **permanent freezing of bridged funds**. [5](#0-4) 

---

### Likelihood Explanation

The condition is reachable by any unprivileged token holder who calls `ft_on_transfer` with a small amount. The decimal gap between origin and NEAR representation is a normal, expected configuration for many tokens (e.g., tokens with 24 origin decimals capped to 18 on NEAR). A user who sends, say, 500,000 units of such a token (a valid, non-zero, fee-satisfying amount on NEAR) will trigger the freeze silently — the `init_transfer` call succeeds and emits an `InitTransferEvent`, giving no indication that the transfer can never be finalized.

---

### Recommendation

Add the normalization check inside `init_transfer`, before tokens are locked or burned. Retrieve the token's `Decimals` for the destination chain at transfer initiation time and assert:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the fix recommended for GDACurve: validate the computed value against its minimum bound at the point of state change, not at a later, separate entry point.

---

### Proof of Concept

1. Deploy a token with `origin_decimals = 24`, `decimals = 18` (diff = 6).
2. User calls `ft_on_transfer` transferring `amount = 500_000` with `fee = 0`. The check `fee < amount` passes. Tokens are burned. Transfer stored with nonce N.
3. Relayer calls `sign_transfer(transfer_id = {Near, N}, ...)`.
4. `normalize_amount(500_000, Decimals { origin: 24, decimals: 18 })` = `500_000 / 1_000_000` = **0**.
5. `require!(0 > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
6. The transfer record remains in `pending_transfers` forever; the 500,000 tokens are permanently burned with no recourse. [1](#0-0) [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
