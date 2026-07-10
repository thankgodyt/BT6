### Title
Unconditional `min_withdraw_amount` Guard in `ft_on_transfer` Blocks `DepositProtocolFee` for Sub-Minimum Amounts - (File: contracts/satoshi-bridge/src/api/token_receiver.rs)

### Summary
In `ft_on_transfer`, the `min_withdraw_amount` check is applied unconditionally before the message type is dispatched. This means `DepositProtocolFee` calls with amounts below `min_withdraw_amount` always revert, even though the withdrawal minimum is semantically irrelevant to protocol fee deposits.

### Finding Description
`ft_on_transfer` handles two distinct message variants: `DepositProtocolFee` and `Withdraw`. Before dispatching on the message type, the function unconditionally enforces:

```rust
require!(
    amount >= self.internal_config().min_withdraw_amount,
    "Invalid amount"
);
``` [1](#0-0) 

Only after this guard does the code branch on the message:

```rust
match message {
    TokenReceiverMessage::DepositProtocolFee => { ... }
    TokenReceiverMessage::Withdraw { ... } => { ... }
}
``` [2](#0-1) 

The `min_withdraw_amount` limit is a withdrawal policy — it exists to prevent economically unviable withdrawals from consuming bridge resources. It has no logical relationship to `DepositProtocolFee`, which simply credits `acc_collected_protocol_fee` and `cur_available_protocol_fee`: [3](#0-2) 

The `min_withdraw_amount` is a configurable field in `Config`: [4](#0-3) 

### Impact Explanation
Any `ft_transfer_call` to the bridge contract carrying a `DepositProtocolFee` message with an `amount` below `min_withdraw_amount` will unconditionally panic and revert. The nBTC tokens are returned to the sender by the NEP-141 standard on panic, so no funds are lost — but the protocol fee deposit operation is permanently broken for sub-minimum amounts. This constitutes harmful smart-contract behavior: the bridge's fee-collection mechanism is partially non-functional, and any integrator or operator attempting to deposit small protocol fee tranches will have their transactions silently rejected with a misleading `"Invalid amount"` error that implies a withdrawal constraint rather than a fee-deposit constraint.

**Matched impact class:** Medium — harmful smart-contract behavior without direct funds theft; broken bridge operational path requiring operator awareness.

### Likelihood Explanation
The `DepositProtocolFee` path is a publicly reachable entry point callable by any nBTC token holder via `ft_transfer_call`. The `min_withdraw_amount` is a configurable value that can be set to a non-trivial satoshi amount. Any caller attempting to deposit protocol fees in an amount below that threshold — a plausible operational scenario — will trigger the revert. No special privileges or conditions are required.

### Recommendation
Move the `min_withdraw_amount` guard inside the `Withdraw` arm of the `match` statement, so it only applies to withdrawal operations:

```rust
fn ft_on_transfer(...) -> PromiseOrValue<U128> {
    let amount = amount.into();
    let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
    let token_id = env::predecessor_account_id();
    require!(token_id == self.internal_config().nbtc_account_id, "Invalid token_id");
    match message {
        TokenReceiverMessage::DepositProtocolFee => { ... }
        TokenReceiverMessage::Withdraw { ... } => {
            require!(
                amount >= self.internal_config().min_withdraw_amount,
                "Invalid amount"
            );
            self.ft_on_transfer_withdraw_chain_specific(...)
        }
    }
}
```

### Proof of Concept
1. Operator calls `ft_transfer_call` on the nBTC contract, transferring `X` nBTC to the bridge contract where `X < min_withdraw_amount`, with `msg = '{"DepositProtocolFee"}'`.
2. The bridge's `ft_on_transfer` is invoked.
3. Before dispatching on the message type, the unconditional `require!(amount >= self.internal_config().min_withdraw_amount, "Invalid amount")` fires and panics.
4. The NEP-141 standard returns the full `X` nBTC to the sender.
5. The protocol fee is never credited; the operation fails with a misleading withdrawal-related error message.

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L29-33)
```rust
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L40-66)
```rust
        match message {
            TokenReceiverMessage::DepositProtocolFee => {
                self.data_mut().acc_collected_protocol_fee += amount;
                self.data_mut().cur_available_protocol_fee += amount;
                Event::DepositProtocolFee {
                    account_id: &sender_id,
                    amount: U128(amount),
                }
                .emit();
                PromiseOrValue::Value(U128(0))
            }
            TokenReceiverMessage::Withdraw {
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            } => self.ft_on_transfer_withdraw_chain_specific(
                sender_id,
                amount,
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            ),
        }
```

**File:** contracts/satoshi-bridge/src/config.rs (L74-76)
```rust
    #[serde(with = "u128_dec_format")]
    pub min_withdraw_amount: u128,
    // The minimum value requirement that change address must satisfy in BTC transaction.
```
