### Title
Direct nBTC Transfer to Bridge via `ft_transfer` Bypasses Withdrawal Flow, Permanently Locking User Funds - (File: contracts/nbtc/src/lib.rs)

---

### Summary

The nBTC token contract's `ft_transfer` function does not prevent users from directly transferring nBTC to the bridge contract. Unlike `ft_transfer_call`, a plain `ft_transfer` to the bridge does not trigger `ft_on_transfer`, so no withdrawal is initiated and no `BTCPendingInfo` is created. The transferred tokens are permanently locked in the bridge's nBTC balance with no user-accessible recovery path.

---

### Finding Description

The intended withdrawal flow is:

1. User calls `ft_transfer_call(bridge_id, amount, msg)` on the nBTC contract.
2. The nBTC contract calls `ft_on_transfer(sender_id, amount, msg)` on the bridge.
3. The bridge parses the `TokenReceiverMessage::Withdraw` payload, validates the PSBT, and creates a `BTCPendingInfo` record.
4. After on-chain confirmation, the bridge calls `burn()` on the nBTC contract to destroy the tokens.

However, a user can instead call `ft_transfer(bridge_id, amount, None)` directly. The bridge is pre-registered as an account in the nBTC token from the constructor:

```rust
// contracts/nbtc/src/lib.rs:88
contract.token.internal_register_account(&contract.bridge_id);
```

The `ft_transfer` override in the nBTC contract only has a special-case guard for `receiver_id == env::current_account_id()` (the nBTC contract itself) with a `"WITHDRAW_TO:"` memo prefix. There is no guard for `receiver_id == bridge_id`:

```rust
// contracts/nbtc/src/lib.rs:183-196
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    // Legacy bridging flow used by Near Intents
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer(withdraw_relayer, amount, memo);
        }
    }
    self.token.ft_transfer(receiver_id, amount, memo);  // bridge_id accepted silently
}
```

Because the bridge is registered, `self.token.ft_transfer(bridge_id, amount, None)` succeeds. The nBTC tokens land in the bridge's balance, but no `ft_on_transfer` callback fires, no `BTCPendingInfo` is created, and no BTC withdrawal is ever initiated.

The developers were aware of the risk of unintended transfers to the bridge in other contexts — `handle_post_action` explicitly blocks it:

```rust
// contracts/nbtc/src/lib.rs:397-400
require!(
    receiver_id != self.bridge_id,
    "handle_post_action: receiver_id must not be the bridge"
);
```

This guard was not applied to `ft_transfer`.

The bridge's `burn` function withdraws from the bridge's own nBTC balance:

```rust
// contracts/nbtc/src/lib.rs:158-159
self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
```

Tokens deposited via a rogue `ft_transfer` inflate the bridge's nBTC balance without any corresponding `BTCPendingInfo` record, creating a silent accounting divergence between tracked withdrawal obligations and actual token holdings.

---

### Impact Explanation

Any nBTC holder who calls `ft_transfer(bridge_id, amount, None)` — whether by mistake or by following outdated/incorrect documentation — permanently loses their tokens. The tokens accumulate in the bridge's nBTC balance with no user-accessible recovery mechanism. The only recovery path is a privileged operator call to `internal_withdraw_protocol_fee`, which transfers from the bridge's balance to the caller but requires a `DAO` or `Operator` role. This matches the original report's conclusion: *"the locked shares can only be retrieved by a protocol update."*

Additionally, the inflated bridge balance creates an accounting invariant violation: the bridge holds more nBTC than the sum of all active `BTCPendingInfo.burn_amount` values, which can mask future accounting errors.

---

### Likelihood Explanation

The `ft_transfer` function is a standard, publicly callable NEP-141 entry point. Any registered nBTC holder can invoke it with 1 yoctoNEAR attached. The bridge is a registered account, so the call succeeds silently with no error. A user unfamiliar with the distinction between `ft_transfer` and `ft_transfer_call`, or one following a third-party integration guide, can easily trigger this path. The risk is further elevated because the nBTC contract itself already has a special `ft_transfer` path (the `WITHDRAW_TO:` legacy flow), which signals that users are expected to use `ft_transfer` for bridge interactions in some contexts.

---

### Recommendation

Add a guard in `ft_transfer` to reject direct transfers to the bridge, mirroring the existing guard in `handle_post_action`:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    require!(
        receiver_id != self.bridge_id,
        "ft_transfer: use ft_transfer_call to initiate a withdrawal"
    );
    // ... existing legacy flow logic ...
    self.token.ft_transfer(receiver_id, amount, memo);
}
```

Alternatively, unregister the bridge account from the nBTC token so that direct transfers to it are rejected at the NEP-141 storage layer.

---

### Proof of Concept

1. Alice holds 100,000 nBTC satoshis.
2. Alice calls `nbtc.ft_transfer({ receiver_id: "bridge.near", amount: "100000", memo: null })` with 1 yoctoNEAR attached.
3. The nBTC contract executes `self.token.ft_transfer("bridge.near", 100000, None)` — no guard fires.
4. Alice's balance drops to 0; the bridge's nBTC balance increases by 100,000.
5. No `ft_on_transfer` is called on the bridge; no `BTCPendingInfo` is created; no BTC withdrawal is queued.
6. Alice's 100,000 nBTC are permanently locked in the bridge.
7. Recovery requires a DAO/Operator to call `withdraw_protocol_fee` and manually return the funds — there is no automated or user-initiated recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/nbtc/src/lib.rs (L86-89)
```rust
        contract
            .token
            .internal_register_account(&contract.bridge_id);

```

**File:** contracts/nbtc/src/lib.rs (L156-159)
```rust
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
```

**File:** contracts/nbtc/src/lib.rs (L183-196)
```rust
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }
```

**File:** contracts/nbtc/src/lib.rs (L397-400)
```rust
        require!(
            receiver_id != self.bridge_id,
            "handle_post_action: receiver_id must not be the bridge"
        );
```

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L11-21)
```rust
    pub fn internal_withdraw_protocol_fee(&self, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .withdraw_protocol_fee_callback(amount.into()),
            )
    }
```
