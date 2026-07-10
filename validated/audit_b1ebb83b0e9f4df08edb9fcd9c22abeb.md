### Title
User Cannot Self-Cancel a Pending Withdrawal — Funds Locked Without Operator Intervention - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
Once a user initiates a withdrawal by transferring nBTC to the bridge via `ft_on_transfer`, they enter a managed pending state with no self-service exit path. The only cancellation function, `cancel_withdraw`, is restricted to `Role::DAO` and `Role::Operator`. If MPC signing stalls or the BTC transaction never confirms, the user's nBTC remains locked in the bridge indefinitely until a privileged operator intervenes.

### Finding Description
When a user calls `ft_on_transfer` with a `Withdraw` message, their nBTC tokens are transferred to the bridge contract and a `BTCPendingInfo` record is created in `PendingInfoState::WithdrawOriginal(PendingInfoStage::PendingSign)` state. [1](#0-0) 

At this point the user's only self-service action is `withdraw_rbf` (to increase the gas fee and accelerate the transaction). There is no user-callable cancellation path. [2](#0-1) 

The sole cancellation function, `cancel_withdraw`, is gated behind `#[access_control_any(roles(Role::DAO, Role::Operator))]`, making it completely inaccessible to the withdrawing user: [3](#0-2) 

The `PendingInfoState` enum defines a `WithdrawCancelRbf` variant, confirming that a cancel-RBF path exists in the state machine — but it is only reachable through the operator-gated `cancel_withdraw` call, never by the user directly. [4](#0-3) 

The `claim_lost_found` function exists for users to reclaim nBTC after a cancel, but it only becomes usable *after* an operator has already executed `cancel_withdraw` and the refund has been routed to `lost_found`. It provides no independent exit path. [5](#0-4) 

This is a direct analog to the AutoCompounder finding: a user transfers ownership of their asset to a managing contract (the bridge), and the managing contract does not expose the full set of operations the user needs (specifically, the ability to exit/cancel). Once opted in, the user cannot opt out without privileged operator action.

### Impact Explanation
If the MPC signing service is unavailable, the BTC transaction is stuck in the mempool indefinitely, or any other operational failure occurs after the user has transferred nBTC to the bridge, the user's nBTC is locked in the bridge contract with no self-service recovery. The user must rely on DAO/Operator to call `cancel_withdraw` to unblock their funds. If the operator is unresponsive, the bridge is paused, or the operator is slow to act, the user's funds remain stuck — a stuck bridge state requiring operator intervention. This matches the allowed medium impact: *"Harmful smart-contract behavior without direct funds theft, including … stuck bridge state requiring operator intervention."*

### Likelihood Explanation
MPC signing is an external asynchronous service. Network congestion, MPC node downtime, or a BTC transaction that is never mined (e.g., fee too low at time of submission) are realistic operational scenarios. The user has no timeout-based self-service exit, so any such failure immediately produces the stuck state. Likelihood is medium.

### Recommendation
Add a user-callable `cancel_withdraw` path protected by a timelock (e.g., the user may cancel only after `N` seconds have elapsed since `create_time_sec` without the transaction reaching `PendingVerify` stage). This mirrors the refund system's `refund_timelock_sec` pattern already present in the codebase: [6](#0-5) 

Alternatively, document clearly that once a withdrawal is initiated the user has no self-service exit and must contact the operator, so users are aware before transferring their nBTC.

### Proof of Concept
1. User calls `nbtc.ft_transfer_call(bridge, amount, '{"Withdraw": {...}}')`.
2. Bridge receives the nBTC via `ft_on_transfer`, creates `BTCPendingInfo` in `WithdrawOriginal / PendingSign` state. nBTC is now held by the bridge.
3. MPC signing service goes offline (or the signed BTC transaction is never broadcast / never confirms).
4. User attempts to recover their nBTC. Their only available call is `withdraw_rbf`, which only increases the fee — it does not cancel or return funds.
5. User attempts to call `cancel_withdraw` directly. The call panics: `access_control_any` rejects any caller without `Role::DAO` or `Role::Operator`.
6. `claim_lost_found` returns "The account does not have lostfound" because no operator has yet executed a cancel.
7. User's nBTC remains locked in the bridge contract indefinitely until an operator acts.

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L51-66)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-460)
```rust
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L69-77)
```rust
pub enum PendingInfoState {
    WithdrawOriginal(OriginalState),
    WithdrawUserRbf(RbfState),
    WithdrawCancelRbf(RbfState),
    ActiveUtxoManagementOriginal(OriginalState),
    ActiveUtxoManagementRbf(RbfState),
    ActiveUtxoManagementCancelRbf(RbfState),
    Refund(OriginalState),
}
```

**File:** contracts/satoshi-bridge/src/refund.rs (L215-228)
```rust
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```
