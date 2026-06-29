### Title
Transfer Permanently Stuck When Normalized Amount Rounds to Zero — (`near/omni-bridge/src/lib.rs`)

### Summary

The bridge's two-phase transfer flow (`init_transfer` → `sign_transfer`) has a missing pre-condition check. Phase 1 (`init_transfer`) burns or locks the user's tokens and stores the transfer in `pending_transfers` without verifying that the amount survives decimal normalization. Phase 2 (`sign_transfer`) then enforces `amount_to_transfer > 0` after normalization, causing a permanent revert with no recovery path. The user's funds are irrecoverably lost.

### Finding Description

The bridge uses a two-phase flow for outbound transfers:

**Phase 1 — `init_transfer`** (called from `ft_on_transfer`): [1](#0-0) 

The only amount validation is `fee < amount`. The function then burns or locks the user's tokens and stores the `TransferMessage` in `pending_transfers`. There is no check that `normalize_amount(amount - fee) > 0`.

**Phase 2 — `sign_transfer`** (called by a trusted relayer): [2](#0-1) 

`normalize_amount` performs floor division: [3](#0-2) 

For any token where `origin_decimals > decimals` (e.g., 24 vs 18, giving a divisor of 10^6), any `amount_without_fee < 10^6` normalizes to zero. The `require!` at line 482 then panics unconditionally on every future call to `sign_transfer` for that transfer ID.

**No recovery path exists.** `remove_transfer_message` is only called inside `sign_transfer_callback` (when MPC signing succeeds and fee is zero) and `claim_fee_callback`. Since `sign_transfer` panics before the MPC call is ever made, neither callback is ever reached. The transfer record stays in `pending_transfers` forever, and the burned/locked tokens are unrecoverable. [4](#0-3) 

### Impact Explanation

For bridged tokens (deployed by the bridge), the token is **burned** on NEAR in `init_transfer_internal` before `sign_transfer` is ever called. The corresponding mint on the destination chain never happens. The user suffers a permanent, total loss of the transferred amount. For native NEAR-origin tokens, the amount is **locked** in the bridge contract with no unlock path. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation

Any token registered with `origin_decimals > decimals` (a normal configuration — e.g., a 24-decimal origin token mapped to 18 NEAR decimals) is affected. A user sending fewer than `10^(origin_decimals - decimals)` units triggers the bug. This can happen accidentally (small dust transfers) or deliberately. The entry point is the standard NEP-141 `ft_transfer_call`, callable by any token holder with no special privileges.

### Recommendation

Add the normalization check inside `init_transfer` before burning/locking tokens and storing the transfer:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the fix applied to the Celo `Random` contract (PR #2795), which rejected the problematic input at commitment time rather than allowing it to be stored and then failing irrecoverably at reveal time.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (divisor = 10^6).
2. User calls `ft_transfer_call` sending `amount = 500_000` units with `fee = 0`.
3. `ft_on_transfer` → `init_transfer`: check `0 < 500_000` passes; tokens are burned; transfer stored.
4. Relayer calls `sign_transfer`: `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`; `require!(0 > 0)` panics.
5. No MPC call is made; `sign_transfer_callback` is never reached; `remove_transfer_message` is never called.
6. The transfer is permanently stuck; the 500,000 burned tokens are unrecoverable. [5](#0-4) [2](#0-1) [3](#0-2)

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
