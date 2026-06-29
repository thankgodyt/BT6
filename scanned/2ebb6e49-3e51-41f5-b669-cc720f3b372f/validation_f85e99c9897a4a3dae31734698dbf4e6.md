### Title
Lack of Input Validation in `init_transfer` Allows Dust Amounts That Normalize to Zero, Permanently Freezing User Funds — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`init_transfer` accepts any token amount that satisfies `fee.fee < amount`, but never verifies that the net amount (after fee) will survive decimal normalization to the destination chain. When `normalize_amount(amount − fee, decimals)` rounds down to zero due to a large decimal-precision gap, `sign_transfer` permanently reverts with `InvalidAmountToTransfer`, and there is no cancellation path. The user's tokens are locked in the bridge forever.

---

### Finding Description

When a user bridges a NEAR NEP-141 token to a foreign chain via `ft_transfer_call`, the bridge's `ft_on_transfer` entry point dispatches to `init_transfer`. The only amount-related guard there is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

This check passes for any positive amount with a fee strictly less than it (including `amount = 1, fee = 0`). The transfer message is then stored in `pending_transfers` and the full token amount is retained by the bridge (the function returns `U128(0)` to the NEP-141 runtime, meaning zero tokens are refunded).

Later, when a relayer calls `sign_transfer`, the bridge computes:

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
``` [2](#0-1) 

`normalize_amount` performs integer floor-division to convert from the NEAR token's `origin_decimals` to the destination chain's `decimals`. The `Decimals` struct stores both values:

```rust
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
``` [3](#0-2) 

When `origin_decimals > decimals` (e.g., a NEAR token with 24 decimals bridging to an EVM chain token with 18 decimals), the normalization divides by `10^(origin_decimals − decimals)`. Any `amount_without_fee < 10^(origin_decimals − decimals)` produces zero after normalization. The `require!` at `sign_transfer` then reverts every signing attempt.

There is no `cancel_transfer` or equivalent recovery function visible in the contract. The only mutation paths for a pending transfer are `sign_transfer` (which reverts) and `update_transfer_fee` (which only adjusts the fee, not the amount, and cannot unblock a zero-normalized amount). [4](#0-3) 

---

### Impact Explanation

The user's tokens are transferred into the bridge contract at `ft_transfer_call` time. Because `ft_on_transfer` returns `U128(0)`, the NEP-141 runtime does not refund them. The transfer record sits in `pending_transfers` indefinitely. Every call to `sign_transfer` reverts. With no cancellation mechanism, the funds are permanently frozen — matching the critical impact class of **permanent freezing of bridged funds**.

---

### Likelihood Explanation

This is reachable by any unprivileged bridge user. Tokens with a large decimal gap between NEAR representation and destination chain representation are common (e.g., wNEAR: 24 decimals on NEAR, 18 on EVM; gap = 6, so any amount below `1,000,000` yocto-units normalizes to zero). A user sending a dust amount — whether by mistake, via a frontend rounding error, or deliberately to grief themselves — triggers the freeze. No special role or privilege is required.

---

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before storing the transfer message. Retrieve the destination token's `Decimals` and assert that `normalize_amount(amount − fee, decimals) > 0`. If the check fails, return the full `amount` to the caller (i.e., refund via the NEP-141 return value) rather than storing an unsignable transfer.

```rust
// Pseudocode addition inside init_transfer, after fee check:
if let Some(token_address) = self.get_token_address(destination_chain, token_id.clone()) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let net = transfer_message.amount_without_fee().expect("fee < amount");
        require!(
            Self::normalize_amount(net, decimals) > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
    }
}
```

---

### Proof of Concept

1. A NEAR token `wNEAR` is registered with `origin_decimals = 24` and `decimals = 18` for the Ethereum destination.
2. Alice calls `ft_transfer_call` on `wNEAR` with `amount = 500_000` (0.0000000000000000005 NEAR) and `msg = InitTransfer { fee: 0, recipient: Eth(0x...), ... }`.
3. `ft_on_transfer` → `init_transfer`: the check `0 < 500_000` passes; the transfer is stored; `U128(0)` is returned, so Alice's 500,000 yocto-wNEAR are locked in the bridge.
4. A relayer calls `sign_transfer`. `normalize_amount(500_000, {decimals:18, origin_decimals:24})` = `500_000 / 10^6 = 0`.
5. `require!(0 > 0)` → panics with `InvalidAmountToTransfer`. The call reverts.
6. Steps 4–5 repeat for every relayer attempt. Alice has no `cancel_transfer` to call. Her 500,000 yocto-wNEAR are permanently frozen. [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L388-436)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L447-485)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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

**File:** near/omni-bridge/src/storage.rs (L132-136)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
