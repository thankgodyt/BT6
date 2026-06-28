### Title
Missing Pre-Transfer Amount Normalization Check Causes Permanent Fund Loss on NEAR → Foreign Chain Transfers - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` on the NEAR hub accepts and irrevocably locks/burns user tokens without verifying that the transferred amount, after decimal normalization, will be non-zero on the destination chain. The `normalize_amount > 0` guard exists only in `sign_transfer`, which is called later by a trusted relayer. Any transfer whose `(amount - fee)` is below the decimal-scaling threshold is permanently undeliverable, and the user's tokens are permanently lost with no recovery path.

### Finding Description

The NEAR `omni-bridge` contract splits the outbound transfer lifecycle into two steps:

1. **`init_transfer`** (user-initiated, via `ft_on_transfer`): accepts tokens, stores the pending transfer, and locks or burns the user's tokens.
2. **`sign_transfer`** (relayer-initiated): normalizes the amount to the destination chain's decimal precision and requests an MPC signature.

The `normalize_amount` function performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

For a NEAR-native token with 24 decimals bridging to an EVM chain registered with 18 decimals, the divisor is `10^6`. Any `(amount - fee) < 1_000_000` normalizes to `0`.

The guard that rejects a zero normalized amount lives exclusively in `sign_transfer`:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

`init_transfer` only checks `fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

It then immediately locks or burns the tokens and returns `U128(0)` (all tokens consumed):

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
...
U128(0)
``` [4](#0-3) 

There is no public `cancel_transfer` function. The only call to `remove_transfer_message` (with refund semantics) is inside `claim_fee_callback`, which requires a proof of finalization on the destination chain — a proof that can never exist for a transfer that was never signed. [5](#0-4) 

### Impact Explanation

A user who sends `(amount - fee) < 10^(origin_decimals - dest_decimals)` base units of a token loses those tokens permanently. The tokens are locked or burned at `init_transfer` time, the pending transfer record is stored, but every subsequent call to `sign_transfer` by any trusted relayer will revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`. No on-chain path exists to recover the locked/burned tokens. This constitutes a permanent, irreversible loss of bridged funds.

### Likelihood Explanation

The condition is reachable by any unprivileged user calling `ft_transfer_call` on any registered NEAR token whose `origin_decimals > dest_decimals`. For the common NEAR (24 decimals) → EVM (18 decimals) pair the threshold is 1,000,000 base units — a realistic "dust" amount. A user sending a small test transfer, or a user whose amount is just below the threshold due to a UI rounding error, triggers the bug. No special role or privilege is required.

### Recommendation

Add the normalization check inside `init_transfer` (or `init_transfer_internal`) before tokens are locked/burned:

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

This mirrors the guard already present in `sign_transfer` and ensures that any transfer that would be undeliverable is rejected at the source before funds are consumed.

### Proof of Concept

1. Register a NEAR token with `origin_decimals = 24`, `decimals = 18` for an EVM destination chain.
2. Call `ft_transfer_call` with `amount = 500_000` (below the `10^6` threshold) and `fee = 0`, targeting the EVM chain.
3. Observe: `ft_on_transfer` → `init_transfer` → `init_transfer_internal` succeeds; tokens are burned/locked; `U128(0)` is returned (tokens consumed).
4. Trusted relayer calls `sign_transfer` for the resulting `TransferId`.
5. Observe: `normalize_amount(500_000, {decimals:18, origin_decimals:24}) = 500_000 / 1_000_000 = 0`; the `require!(amount_to_transfer > 0)` guard panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
6. The transfer remains in `pending_transfers` indefinitely; the user's 500,000 base-unit tokens are permanently lost. [6](#0-5) [2](#0-1) [1](#0-0)

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

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
