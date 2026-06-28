### Title
Hard-Coded Zero-Amount Guard in `sign_transfer` Permanently Freezes User Funds When Decimal Normalization Rounds to Zero - (File: near/omni-bridge/src/lib.rs)

### Summary

In `near/omni-bridge/src/lib.rs`, the `sign_transfer` function applies a hard-coded `require!(amount_to_transfer > 0)` guard after decimal normalization. When a user's `amount_without_fee` is smaller than the precision unit of the destination chain (i.e., `normalize_amount` floors to 0), `sign_transfer` panics unconditionally. Because there is no cancel or refund path for a pending transfer, the user's tokens are permanently locked in the bridge contract.

---

### Finding Description

When a user initiates a transfer via `ft_on_transfer` → `init_transfer`, their tokens are transferred into the bridge contract and a `TransferMessage` is stored in `pending_transfers`. A trusted relayer later calls `sign_transfer` to obtain an MPC signature and finalize the outbound transfer.

Inside `sign_transfer`, the net amount is computed and then normalized from the NEAR token's native decimal precision (`origin_decimals`) to the destination chain's decimal precision (`decimals`):

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

`normalize_amount` performs integer (floor) division. When `origin_decimals > decimals` (e.g., a NEAR token with 24 decimals bridging to an EVM chain where the token has 6 decimals), any `amount_without_fee` smaller than `10^(origin_decimals − decimals)` = `10^18` normalizes to 0. The hard-coded `require!` then causes `sign_transfer` to panic every time it is called for that transfer.

The `TransferMessage` is never removed from `pending_transfers` on a panic — removal only occurs inside `sign_transfer_callback` (when `fee.is_zero()`) or `claim_fee_callback`. Neither path is reachable when `sign_transfer` itself panics before reaching the MPC call. The `update_transfer_fee` function cannot help the user recover funds: it only allows the fee to be *increased* (new fee ≥ current fee), which makes `amount_without_fee` even smaller.

There is no `cancel_transfer` or user-initiated refund function anywhere in the contract.

---

### Impact Explanation

User tokens are permanently frozen inside the bridge contract. The `pending_transfers` entry can never be removed because the only removal paths require `sign_transfer` to succeed past the hard-coded guard, which it never will for this transfer. This matches the **Critical** impact class: permanent freezing of bridged funds.

---

### Likelihood Explanation

The condition is reachable by any unprivileged user in two realistic ways:

1. **Small transfer amount**: A user sends fewer than `10^(origin_decimals − dest_decimals)` base units of a token (e.g., less than `10^18` yocto-units of a 24-decimal NEAR token bridging to a 6-decimal EVM token). This is a plausible mistake for users unfamiliar with decimal representations.

2. **Fee consumes most of the amount**: A user sets a fee close to the total amount, leaving an `amount_without_fee` that normalizes to 0. For example, sending 1000 units with a fee of 999 units leaves 1 unit, which normalizes to 0 across an 18-decimal gap.

Both scenarios are reachable without any privileged access.

---

### Recommendation

Two mitigations should be applied together:

1. **Validate at `init_transfer` time**: Compute and check the normalized amount before locking user tokens. Reject the transfer immediately (returning the tokens) if the normalized `amount_without_fee` would be 0, rather than allowing funds to be locked and only discovering the problem later during `sign_transfer`.

2. **Add a user-initiated cancel path**: Provide a `cancel_transfer` function that allows the original sender to reclaim their tokens from a pending transfer that cannot be finalized (e.g., after a timeout or when the normalized amount is 0). This is the bridge analog to the report's recommendation of letting users control the slippage parameter.

---

### Proof of Concept

1. Token `T` is registered with `origin_decimals = 24`, `decimals = 6` (18-decimal gap).
2. User calls `ft_transfer_call` on token `T` sending `amount = 500` (in 24-decimal base units) with `fee = 499`, so `amount_without_fee = 1`.
3. `init_transfer` succeeds: 500 units of `T` are locked in the bridge; `TransferMessage` is stored in `pending_transfers`.
4. Trusted relayer calls `sign_transfer`.
5. `normalize_amount(1, Decimals { decimals: 6, origin_decimals: 24 })` = `1 / 10^18` = `0` (floor division).
6. `require!(0 > 0, ...)` panics with `BridgeError::InvalidAmountToTransfer`.
7. The relayer's transaction is reverted; `pending_transfers` still holds the entry.
8. Every subsequent call to `sign_transfer` for this transfer ID panics identically.
9. The user's 500 units of `T` are permanently frozen with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L648-668)
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
    }
```

**File:** near/omni-bridge/src/storage.rs (L131-136)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
