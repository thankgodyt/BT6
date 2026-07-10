### Title
Users Cannot Self-Cancel a Stuck Withdrawal, Permanently Locking nBTC in the Bridge — (`contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`cancel_withdraw` is gated exclusively to `Role::DAO` or `Role::Operator`. A user who initiated a withdrawal has no on-chain mechanism to reclaim their nBTC if the BTC transaction stalls and the operator is unavailable. This is the direct bridge analog of the `removeBoostDelegation` access-control lock-in: only the privileged party (operator) can undo an action that the original initiator (user) should also be able to undo.

---

### Finding Description

When a user initiates a withdrawal they call `nbtc.ft_transfer_call(bridge, amount, WithdrawMsg)`. The NEP-141 standard transfers the tokens to the bridge contract; `ft_on_transfer` returns `U128(0)`, meaning the bridge keeps all tokens. [1](#0-0) 

A `BTCPendingInfo` record is created with state `WithdrawOriginal`. The nBTC is now held by the bridge contract — not yet burned — and the user has no direct claim to it. [2](#0-1) 

If the resulting BTC transaction fails to confirm (mempool congestion, fee too low, network issue), the user can call `withdraw_rbf` to bump the fee, but that function enforces `original_tx_btc_pending_info.account_id == account_id`, so only the original withdrawer can call it. [3](#0-2) 

To actually **cancel** the withdrawal and recover the nBTC, the only available function is `cancel_withdraw`, which is decorated with `#[access_control_any(roles(Role::DAO, Role::Operator))]`: [4](#0-3) 

The internal implementation (`internal_cancel_withdraw`) constructs a cancel-RBF PSBT that redirects the UTXOs back to the change address, and only after that cancel BTC transaction is signed, broadcast, and verified on-chain does the bridge return the remaining nBTC to the user. [5](#0-4) 

There is no code path that allows the withdrawing user to trigger this cancellation themselves. The `claim_lost_found` function only helps if a prior `cancel_withdraw` callback already failed; it does not substitute for the missing user-callable cancel path. [6](#0-5) 

---

### Impact Explanation

A user's nBTC is transferred to the bridge at withdrawal initiation and remains locked there until either the BTC transaction confirms (triggering `verify_withdraw` → burn) or DAO/Operator calls `cancel_withdraw`. If the operator is unresponsive, the bridge is paused, or the operator key is unavailable, the user's nBTC is stuck indefinitely with no self-rescue path. This constitutes a **stuck bridge state requiring operator intervention** — a Medium impact per the allowed scope.

---

### Likelihood Explanation

Any withdrawal whose BTC transaction fails to confirm triggers this condition. Bitcoin mempool congestion is a routine occurrence. The user's only recourse (`withdraw_rbf`) can only increase the fee, not cancel. If the operator is slow, offline, or the bridge is paused, the lock-in persists for an unbounded duration. The entry path is fully unprivileged: any user who calls `ft_transfer_call` with a `Withdraw` message is exposed.

---

### Recommendation

Allow the original withdrawing user to call `cancel_withdraw` on their own pending transaction. The function already reads `account_id` from the stored `BTCPendingInfo`, so the caller identity can be verified:

```rust
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    let pending = self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
    let user_account_id = pending.account_id.clone();
    let caller = env::predecessor_account_id();
    let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
        || self.acl_has_role(Role::Operator.into(), caller.clone());
    require!(
        is_privileged || caller == user_account_id,
        "Only DAO/Operator or the original withdrawer can cancel"
    );
    // ... rest of logic unchanged
}
```

This mirrors the fix recommended in the external report: permit either the privileged party or the original initiator to execute the removal.

---

### Proof of Concept

1. Alice calls `nbtc.ft_transfer_call(bridge, 100_000, WithdrawMsg{...})`. Bridge keeps 100,000 nBTC; `BTCPendingInfo` created with `account_id = alice`.
2. The BTC transaction is signed by MPC and broadcast but never confirms (e.g., fee too low for current mempool).
3. Alice calls `withdraw_rbf` repeatedly but the transaction remains unconfirmed.
4. Alice attempts `cancel_withdraw(pending_id, output)` — the call is rejected by `#[access_control_any(roles(Role::DAO, Role::Operator))]` because Alice holds neither role.
5. The operator is offline. Alice's 100,000 nBTC remains locked in the bridge contract with no on-chain mechanism to recover it. [4](#0-3) [7](#0-6)

### Citations

**File:** CLAUDE.md (L47-54)
```markdown
1. User: nbtc.ft_transfer(bridge, amount, WithdrawMsg)
   → Tokens TRANSFERRED to bridge (not burned yet!)
2. nBTC: bridge.ft_on_transfer(user, amount, msg) → Bridge returns 0 (keeps tokens)
3. Bridge creates BTC tx, Chain Signatures signs
4. Tx broadcast to Bitcoin network
5. Relayer: bridge.verify_withdraw(tx_proof)
6. Bridge verifies → calls nbtc.burn(user, amount, relayer, fee)
   → Burns from bridge balance (tokens already there!)
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L22-67)
```rust
    #[pause(except(roles(Role::DAO)))]
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

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L43-46)
```rust
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-299)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L448-460)
```rust
    /// Cancel Withdraw will refund the remaining nBTC to the user. If the refund fails, the user can retrieve it again through this interface.
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_lost_found(&mut self) -> Promise {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let amount = self
            .data_mut()
            .lost_found
            .remove(&account_id)
            .expect("The account does not have lostfound");
        self.internal_transfer_nbtc(&account_id, amount)
    }
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L22-77)
```rust
    pub fn internal_cancel_withdraw(
        &mut self,
        _account_id: &AccountId,
        original_btc_pending_verify_id: String,
        cancel_withdraw_rbf_psbt: PsbtWrapper,
        predecessor_account_id: AccountId,
    ) -> String {
        let original_tx_btc_pending_info =
            self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
        require!(
            nano_to_sec(env::block_timestamp()) - original_tx_btc_pending_info.create_time_sec
                > self.internal_config().max_btc_tx_pending_sec,
            "Please wait user rbf"
        );
        original_tx_btc_pending_info.assert_not_canceled();
        original_tx_btc_pending_info.assert_withdraw_original_pending_verify_tx();

        let mut btc_pending_info = init_rbf_btc_pending_info(
            original_tx_btc_pending_info,
            PendingInfoState::WithdrawCancelRbf(RbfState {
                stage: PendingInfoStage::PendingSign,
                original_tx_id: original_btc_pending_verify_id.clone(),
            }),
        );
        let (actual_received_amount, gas_fee) = self.check_cancel_withdraw_rbf_psbt_valid(
            original_tx_btc_pending_info,
            &cancel_withdraw_rbf_psbt,
        );

        btc_pending_info.gas_fee = gas_fee;
        btc_pending_info.burn_amount = gas_fee;
        btc_pending_info.actual_received_amount = actual_received_amount;
        Self::check_withdraw_chain_specific(original_tx_btc_pending_info, gas_fee);
        let excess_gas_fee = gas_fee
            .saturating_sub(btc_pending_info.transfer_amount - btc_pending_info.withdraw_fee);
        if excess_gas_fee > 0 {
            require!(
                self.acl_has_role(Role::DAO.into(), predecessor_account_id),
                "gas fee exceeds the user's balance, only the owner is allowed to cancel"
            );
            require!(
                self.data().cur_available_protocol_fee >= excess_gas_fee,
                "Insufficient protocol fee"
            );
            self.data_mut().cur_available_protocol_fee -= excess_gas_fee;
            self.data_mut().cur_reserved_protocol_fee += excess_gas_fee;
        }
        self.internal_unwrap_mut_btc_pending_info(&original_btc_pending_verify_id)
            .do_cancel(gas_fee, excess_gas_fee);
        self.set_rbf_pending_info(
            &original_btc_pending_verify_id,
            btc_pending_info,
            cancel_withdraw_rbf_psbt,
            true,
        )
    }
```
