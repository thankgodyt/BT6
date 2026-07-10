### Title
User Withdrawal Permanently Stuck When `cancel_withdraw` Reverts Due to Insufficient Protocol Fee During Fee Spike — (`File: contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs`)

### Summary

When a user initiates a withdrawal, their nBTC is burned immediately. If the resulting Bitcoin transaction fails to confirm (low fee) and a subsequent fee spike causes the required cancellation gas fee to exceed both the user's transfer amount and the available protocol fee, the `cancel_withdraw` function reverts entirely. The user has no self-service exit path, and even privileged operator intervention fails. The user's nBTC is permanently burned with no BTC received.

### Finding Description

The withdrawal lifecycle burns nBTC at initiation and creates a `BTCPendingInfo` entry. Once the transaction is broadcast (`PendingVerify` stage), the only operator-controlled cancellation path is `cancel_withdraw` in `cancel_withdraw.rs`. [1](#0-0) 

```rust
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
```

When `excess_gas_fee > 0` and `cur_available_protocol_fee < excess_gas_fee`, the entire call reverts. There is no partial-refund path, no fallback, and no user-callable cancellation.

The user's only self-service option is `withdraw_rbf`, which is restricted to `PendingVerify` state and can only reduce the output amount — it cannot increase the fee beyond the original `transfer_amount`. If the required fee exceeds `transfer_amount - withdraw_fee`, the user cannot RBF their way to confirmation either. [2](#0-1) 

`cancel_withdraw` is gated to `Role::DAO` or `Role::Operator` — the user has zero ability to trigger cancellation themselves regardless of how long their funds are stuck. [3](#0-2) 

`assert_withdraw_original_pending_verify_tx` further restricts cancellation to the `PendingVerify` stage only, so a withdrawal stuck in `PendingSign` (MPC never signs) has no cancellation path at all.

### Impact Explanation

**Medium — stuck bridge state requiring operator intervention (and operator intervention itself fails).**

The user's nBTC is burned at withdrawal initiation. If the Bitcoin transaction is broadcast but never confirmed, and the cancellation mechanism reverts due to `cur_available_protocol_fee < excess_gas_fee`, the user's funds are permanently locked:

- nBTC is already burned (irreversible on NEAR side).
- The BTC UTXO remains unspent in the bridge's control.
- `verify_withdraw_v2` cannot succeed (transaction never confirmed).
- `cancel_withdraw` reverts (insufficient protocol fee).
- `withdraw_rbf` cannot help (fee exceeds transfer amount).

This constitutes permanent loss of user funds without any theft — a stuck bridge state with no recovery path.

### Likelihood Explanation

**Medium.** Bitcoin fee spikes are historically common (e.g., 2023 Ordinals surge, 2024 Runes launch). A user with a small withdrawal (e.g., dust-level nBTC) is especially vulnerable: their `transfer_amount - withdraw_fee` is small, so even a moderate fee spike creates `excess_gas_fee > 0`. If the protocol fee pool has been depleted by prior cancellations, the second `require!` also fails. Both conditions can realistically co-occur.

### Recommendation

1. Allow `cancel_withdraw` to proceed even when `cur_available_protocol_fee < excess_gas_fee` by capping the gas fee at `transfer_amount - withdraw_fee` and accepting a zero-return cancellation (user loses their full transfer amount but the state is resolved).
2. Alternatively, allow the user themselves to trigger a self-service cancellation (analogous to "dequeue escrowed stables") that returns whatever remains after deducting the maximum feasible gas fee, without requiring DAO role or protocol fee subsidy.
3. Add a cancellation path for withdrawals stuck in `PendingSign` state (MPC never signs), so users are not permanently locked out even before broadcast.

### Proof of Concept

1. User calls `ft_transfer_call` on nBTC with `transfer_amount = 1000 sats`, `withdraw_fee = 100 sats`. nBTC is burned.
2. Bridge creates `BTCPendingInfo` (PendingSign → PendingVerify after MPC signs). Transaction broadcast with `gas_fee = 200 sats`.
3. Bitcoin fee spikes. Transaction is not confirmed. `max_btc_tx_pending_sec` elapses.
4. DAO calls `cancel_withdraw` with a new PSBT requiring `gas_fee = 1500 sats`.
5. `excess_gas_fee = 1500 - (1000 - 100) = 600 sats`.
6. `cur_available_protocol_fee = 500 sats < 600 sats` → second `require!` fails → entire call reverts.
7. User calls `withdraw_rbf` with max possible fee reduction: output = `1000 - 100 - 1500 = negative` → impossible, RBF cannot cover the required fee.
8. User's nBTC is burned. BTC is stuck. No recovery path exists. [4](#0-3) [3](#0-2) [2](#0-1)

### Citations

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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L194-199)
```rust
    pub fn assert_withdraw_original_pending_verify_tx(&self) {
        match self.state.borrow() {
            PendingInfoState::WithdrawOriginal(state) => state.assert_pending_verify(),
            _ => env::panic_str("Not withdraw original tx"),
        }
    }
```
