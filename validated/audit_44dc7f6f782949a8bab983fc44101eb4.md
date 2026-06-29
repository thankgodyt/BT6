### Title
`init_transfer` Does Not Validate `normalize_amount(amount - fee) > 0`, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` on NEAR accepts and locks user tokens without verifying that the net transfer amount (after fee) survives decimal normalization to a non-zero value. `sign_transfer` enforces this check, but by then the tokens are already irrecoverably locked with no cancellation path.

### Finding Description

The NEAR bridge uses a two-step outbound flow: `init_transfer` (locks tokens, stores `TransferMessage`) followed by `sign_transfer` (requests MPC signature for the destination chain). Decimal normalization is required because NEAR-side tokens may have higher precision than their destination-chain counterparts.

`sign_transfer` enforces:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [1](#0-0) 

`normalize_amount` performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [2](#0-1) 

`init_transfer` only checks `fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

It does **not** check that `normalize_amount(amount - fee) > 0`. Tokens are locked immediately upon `init_transfer` success.

**Concrete scenario** (token with `origin_decimals = 24`, `decimals = 6`, diff = 18):

1. User calls `ft_transfer_call` → `init_transfer` with `amount = 5 × 10^17` and `fee = 0`.
2. `fee (0) < amount (5×10^17)` passes. Tokens are locked in the bridge.
3. Relayer calls `sign_transfer`.
4. `normalize_amount(5×10^17, {origin_decimals:24, decimals:6}) = 5×10^17 / 10^18 = 0`.
5. `require!(amount_to_transfer > 0)` panics → `sign_transfer` always fails.
6. No cancellation function exists; `remove_transfer_message` is only reachable via `sign_transfer_callback` (requires successful MPC signature) or `claim_fee_callback` (requires a `FinTransfer` proof from the destination chain, which never exists). [4](#0-3) 

### Impact Explanation

User tokens are permanently frozen inside the NEAR `omni-bridge` contract. There is no admin escape hatch, no `cancel_transfer`, and no refund path. The `TransferMessage` remains in `pending_transfers` indefinitely, and the locked token balance is never released. This constitutes **permanent freezing of bridged funds**.

### Likelihood Explanation

Any token pair where `origin_decimals > decimals` (e.g., a 24-decimal NEAR token bridged to a 6-decimal EVM token) creates a minimum transferable unit of `10^(origin_decimals - decimals)`. Users transferring amounts below this threshold — a realistic mistake given no UI-level guard and no on-chain rejection at `init_transfer` — will permanently lose their funds. The `update_transfer_fee` function also allows the sender to raise the token fee post-initiation, which can push a previously valid `amount - fee` below the normalization threshold, triggering the same freeze. [5](#0-4) 

### Recommendation

Add the normalization check inside `init_transfer_internal` (or at the end of `init_transfer`) before storing the `TransferMessage`:

```rust
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

Apply the same guard inside `update_transfer_fee` when the token fee is raised, to prevent a valid transfer from being made un-signable after the fact.

### Proof of Concept

1. Deploy a NEAR token with 24 decimals; bind it to an EVM address with `decimals = 6`, `origin_decimals = 24` via `bind_token`.
2. Call `ft_transfer_call` on the token contract with `amount = 999_999_999_999_999_999` (< 10^18) and `msg` encoding `InitTransferMsg { fee: U128(0), native_token_fee: U128(0), recipient: <EVM address>, ... }`.
3. Observe `init_transfer` succeeds; tokens are deducted from the user and locked in the bridge.
4. Call `sign_transfer` with the resulting `transfer_id`.
5. Observe the call panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` because `normalize_amount(999_999_999_999_999_999) = 0`.
6. Confirm no function exists to recover the locked tokens. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L471-485)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2704-2736)
```rust
    fn add_token(
        &mut self,
        token_id: &AccountId,
        token_address: &OmniAddress,
        decimals: u8,
        origin_decimals: u8,
    ) {
        let chain_kind = token_address.get_chain();
        require!(
            self.token_id_to_address
                .insert(&(chain_kind, token_id.clone()), token_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
        require!(
            self.token_address_to_id
                .insert(token_address, token_id)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
        require!(
            self.token_decimals
                .insert(
                    token_address,
                    &Decimals {
                        decimals,
                        origin_decimals,
                    }
                )
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
