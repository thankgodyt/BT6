### Title
Unconditional `min_withdraw_amount` Check in `ft_on_transfer` Blocks `DepositProtocolFee` Operations — (`contracts/satoshi-bridge/src/api/token_receiver.rs`)

---

### Summary

`ft_on_transfer` handles two semantically distinct message types — `Withdraw` and `DepositProtocolFee` — but unconditionally enforces `min_withdraw_amount` before the message is even parsed. This check is a withdrawal-specific constraint that has no logical relevance to protocol fee deposits, creating a publicly reachable DoS on the `DepositProtocolFee` path for any amount below the withdrawal minimum.

---

### Finding Description

The bridge's NEP-141 receiver callback `ft_on_transfer` accepts two distinct operation types via `TokenReceiverMessage`:

1. `Withdraw` — initiates a BTC/ZEC withdrawal; a minimum amount guard is semantically appropriate here to prevent dust outputs.
2. `DepositProtocolFee` — deposits nBTC into the bridge's protocol fee pool; no minimum amount restriction is semantically justified.

The current implementation applies the withdrawal-specific guard unconditionally, before the message variant is known:

```rust
// contracts/satoshi-bridge/src/api/token_receiver.rs  lines 29-38
let amount = amount.into();
require!(
    amount >= self.internal_config().min_withdraw_amount,
    "Invalid amount"
);
let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
``` [1](#0-0) 

Only after this check does the code branch on the message type:

```rust
match message {
    TokenReceiverMessage::DepositProtocolFee => { ... }
    TokenReceiverMessage::Withdraw { ... } => { ... }
}
``` [2](#0-1) 

The parameter `min_withdraw_amount` is a withdrawal-specific configuration value. Applying it to `DepositProtocolFee` is semantically incorrect and directly analogous to the external report's root cause: a multi-path function unconditionally enforcing a check that belongs only to one of its paths.

---

### Impact Explanation

Any `ft_transfer_call` to the bridge carrying a `DepositProtocolFee` message with `amount < min_withdraw_amount` will panic at the `require!` guard. Under NEP-141 semantics, a panic in `ft_on_transfer` causes the token transfer to be rolled back and the tokens returned to the sender — so no funds are permanently lost. However:

- Protocol fee deposits below the withdrawal minimum are permanently blocked at the contract level, regardless of operator intent.
- The bridge's `acc_collected_protocol_fee` and `cur_available_protocol_fee` accumulators cannot be incremented by small-denomination deposits.
- This is a publicly reachable invariant violation in a production bridge path, matching the **Low** allowed impact: *publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft*. [3](#0-2) 

---

### Likelihood Explanation

The entry path is fully public: any nBTC holder can call `ft_transfer_call` on the nBTC token contract targeting the bridge with a `DepositProtocolFee` JSON message. No privileged role is required. The trigger condition — `amount < min_withdraw_amount` — is determined by the bridge's configuration, which is set by the DAO and can be a non-trivial value (e.g., tens of thousands of satoshis). Any caller attempting a small protocol fee deposit will hit this unconditional guard.

---

### Recommendation

Move the `min_withdraw_amount` check inside the `Withdraw` match arm, where it is semantically appropriate, rather than applying it unconditionally to all message types:

```rust
match message {
    TokenReceiverMessage::DepositProtocolFee => {
        // No minimum amount restriction needed here
        self.data_mut().acc_collected_protocol_fee += amount;
        self.data_mut().cur_available_protocol_fee += amount;
        ...
        PromiseOrValue::Value(U128(0))
    }
    TokenReceiverMessage::Withdraw { ... } => {
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
        self.ft_on_transfer_withdraw_chain_specific(...)
    }
}
```

---

### Proof of Concept

1. DAO configures `min_withdraw_amount = 10_000` satoshis.
2. Any nBTC holder calls `ft_transfer_call(bridge_id, U128(5_000), None, "{\"DepositProtocolFee\"}")` on the nBTC contract.
3. The nBTC contract invokes `ft_on_transfer` on the bridge with `amount = 5_000`.
4. The bridge panics at `require!(5_000 >= 10_000, "Invalid amount")` before the message is parsed.
5. NEP-141 rolls back the transfer; the 5_000 nBTC is returned to the sender.
6. The protocol fee pool is not updated; the operation is silently blocked with no recourse short of a DAO configuration change. [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L23-67)
```rust
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
        let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
        let token_id = env::predecessor_account_id();
        require!(
            token_id == self.internal_config().nbtc_account_id,
            "Invalid token_id"
        );
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
    }
```
