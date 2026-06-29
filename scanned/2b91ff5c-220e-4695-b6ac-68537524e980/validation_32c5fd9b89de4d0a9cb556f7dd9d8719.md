### Title
Asymmetric Burn/Lock Accounting in `fast_fin_transfer_to_other_chain` vs `init_transfer_internal` Causes Deployed-Token Supply Inflation — (File: `near/omni-bridge/src/lib.rs`)

### Summary
`init_transfer_internal` correctly burns and locks the **full transfer amount** (including fee) when a user bridges deployed tokens to another chain. The analogous fast-transfer path `fast_fin_transfer_to_other_chain` burns and locks only `amount_without_fee`, leaving the fee portion of deployed tokens sitting unburned in the bridge's balance. When the relayer later claims the fee via `claim_fee_callback`, `send_fee_internal` **mints** the fee again for deployed tokens, inflating the token supply by the fee amount on every such fast transfer.

### Finding Description

**`init_transfer_internal` (the correctly handled path)** burns and locks the full amount including fee: [1](#0-0) 

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);   // full amount
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,   // full amount
);
```

**`fast_fin_transfer_to_other_chain` (the asymmetric path)** burns and locks only `amount_without_fee`: [2](#0-1) 

```rust
let amount_without_fee = fast_transfer
    .amount_without_fee()
    .near_expect(BridgeError::InvalidFee);

self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());
self.lock_tokens_if_needed(
    fast_transfer.get_destination_chain(),
    &fast_transfer.token_id,
    amount_without_fee,
);
```

Yet the `TransferMessage` created in the same function carries the **full amount** (including fee): [3](#0-2) 

```rust
let transfer_message = TransferMessage {
    ...
    amount: fast_transfer.amount,   // full amount including fee
    fee: fast_transfer.fee.clone(),
    ...
};
```

When the relayer later calls `claim_fee`, `claim_fee_callback` computes `fee = transfer_message.amount.0 - denormalized_amount` and calls `send_fee_internal`. For deployed tokens, `send_fee_internal` **mints** the fee (consistent with `fin_transfer_send_tokens_callback` at lines 1722–1726): [4](#0-3) 

The net effect for deployed tokens per fast-transfer-to-other-chain:
- Bridge **receives** `amount` deployed tokens from relayer.
- Burns only `amount_without_fee` → `fee` tokens remain unburned in bridge balance.
- Mints `fee` again at claim time → **`fee` extra deployed tokens permanently in circulation**.

### Impact Explanation
Every fast transfer to a non-NEAR destination chain inflates the deployed-token supply by the fee amount. A malicious trusted relayer can amplify this by setting a large fee relative to the transfer amount (the only constraint is `amount + fee == denormalized_amount`). Over many transfers this constitutes unauthorized token minting, breaking the lock/burn invariant that backs bridged assets.

Additionally, `locked_tokens` is understated by the fee amount per such transfer, corrupting the accounting used to enforce the supply cap for NEAR-origin tokens bridged to foreign chains. [5](#0-4) 

### Likelihood Explanation
Any active trusted relayer executing fast transfers to non-NEAR destinations triggers this path. The `is_trusted_relayer` gate is the only prerequisite; no admin compromise is required. Trusted relayers are explicitly listed as an in-scope attacker class ("custom relayer"). The path is exercised in normal bridge operation, so inflation accumulates passively even without malicious intent. [6](#0-5) 

### Recommendation
In `fast_fin_transfer_to_other_chain`, burn and lock `fast_transfer.amount.0` (the full amount including fee) instead of `amount_without_fee`, mirroring the behavior of `init_transfer_internal`. This ensures the fee portion of deployed tokens is destroyed on NEAR before being re-minted at claim time, preserving the supply invariant.

### Proof of Concept

1. Deployed token `T` exists (bridge is its controller/minter).
2. Trusted relayer calls `ft_transfer_call` sending `1000 T` to the bridge with `FastFinTransferMsg { amount: 1000, fee: { fee: 100 }, recipient: <EVM address>, ... }`.
3. `fast_fin_transfer_to_other_chain` runs:
   - `amount_without_fee = 900`
   - Burns `900 T` ✓
   - Leaves `100 T` unburned in bridge balance.
   - Creates `TransferMessage { amount: 1000, fee: 100 }`.
4. Transfer is finalized on EVM; recipient receives `900 T` equivalent.
5. Relayer calls `claim_fee` with proof.
6. `claim_fee_callback` computes `fee = 1000 - 900 = 100`, calls `send_fee_internal` → **mints 100 T** to relayer.
7. Bridge still holds the original `100 T` (never burned). Total supply increased by `100 T`. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L756-756)
```rust
        require!(self.is_trusted_relayer(&signer_id), "Relayer is not active");
```

**File:** near/omni-bridge/src/lib.rs (L914-973)
```rust
    fn fast_fin_transfer_to_other_chain(
        &mut self,
        fast_transfer: &FastTransfer,
        storage_payer: AccountId,
        relayer_id: AccountId,
    ) {
        if fast_transfer.recipient.is_utxo_chain() {
            let btc_account_id = self.get_utxo_chain_token(fast_transfer.get_destination_chain());
            require!(
                fast_transfer.token_id == btc_account_id,
                BridgeError::NativeTokenRequiredForChain.as_ref()
            );
        }

        let amount_without_fee = fast_transfer
            .amount_without_fee()
            .near_expect(BridgeError::InvalidFee);

        self.burn_tokens_if_needed(fast_transfer.token_id.clone(), amount_without_fee.into());

        self.lock_tokens_if_needed(
            fast_transfer.get_destination_chain(),
            &fast_transfer.token_id,
            amount_without_fee,
        );

        let mut required_balance =
            self.add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone());

        let destination_nonce =
            self.get_next_destination_nonce(fast_transfer.get_destination_chain());
        self.current_origin_nonce += 1;

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(fast_transfer.token_id.clone()),
            amount: fast_transfer.amount,
            recipient: fast_transfer.recipient.clone(),
            fee: fast_transfer.fee.clone(),
            sender: OmniAddress::Near(env::current_account_id()),
            msg: fast_transfer.msg.clone(),
            destination_nonce,
            origin_transfer_id: Some(fast_transfer.transfer_id.clone()),
        };
        let new_transfer_id = transfer_message.get_transfer_id();

        required_balance = self
            .add_transfer_message(transfer_message, storage_payer.clone())
            .saturating_add(required_balance);

        env::log_str(
            &OmniBridgeEvent::FastTransferEvent {
                fast_transfer: fast_transfer.clone(),
                new_transfer_id: Some(new_transfer_id),
            }
            .to_log_string(),
        );

        self.update_storage_balance(storage_payer, required_balance, NearToken::from_near(0));
    }
```

**File:** near/omni-bridge/src/lib.rs (L1066-1134)
```rust
    #[private]
    #[payable]
    pub fn claim_fee_callback(
        &mut self,
        #[serializer(borsh)] predecessor_account_id: &AccountId,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> PromiseOrValue<()> {
        let Ok(ProverResult::FinTransfer(fin_transfer)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };

        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

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
    }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```
