### Title
Missing Upper-Bound Time Check in `withdraw_rbf` Allows User RBF After Protocol Cancel Window Opens - (File: contracts/satoshi-bridge/src/rbf/withdraw.rs)

### Summary

`internal_withdraw_rbf` has no check that the `max_btc_tx_pending_sec` timeout has **not** elapsed. The cancel functions (`internal_cancel_withdraw`, `internal_cancel_active_utxo_management`) enforce a lower-bound: the protocol may only cancel **after** the timeout. But `withdraw_rbf` enforces no corresponding upper-bound: the user may still submit a user-RBF **after** the timeout, creating two competing signed Bitcoin transactions for the same UTXO set and leaving stale pending state on NEAR.

### Finding Description

`internal_cancel_withdraw` enforces:

```rust
require!(
    nano_to_sec(env::block_timestamp()) - original_tx_btc_pending_info.create_time_sec
        > self.internal_config().max_btc_tx_pending_sec,
    "Please wait user rbf"
);
``` [1](#0-0) 

The error message `"Please wait user rbf"` makes the design intent explicit: before the timeout the user may RBF; after the timeout the protocol may cancel. `internal_cancel_active_utxo_management` has the identical guard. [2](#0-1) 

`internal_withdraw_rbf`, however, performs no time check at all:

```rust
pub fn internal_withdraw_rbf(...) -> String {
    let original_tx_btc_pending_info =
        self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
    require!(
        &original_tx_btc_pending_info.account_id == account_id,
        "Not allow"
    );
    original_tx_btc_pending_info.assert_not_canceled();
    original_tx_btc_pending_info.assert_withdraw_original_pending_verify_tx();
    // ← no check that block_timestamp - create_time_sec <= max_btc_tx_pending_sec
    ...
}
``` [3](#0-2) 

The public entry point `withdraw_rbf` in `api/bridge.rs` also adds no time guard: [4](#0-3) 

Because `assert_not_canceled()` only checks `cancel_rbf_reserved.is_none()`, and `internal_withdraw_rbf` never sets `cancel_rbf_reserved`, the original pending info remains "not canceled" after a user RBF. This means `internal_cancel_withdraw` can still succeed immediately afterward, producing two live signed-transaction candidates (`WithdrawUserRbf` + `WithdrawCancelRbf`) that both spend the same UTXO inputs. [5](#0-4) 

### Impact Explanation

After `max_btc_tx_pending_sec` elapses:

1. User calls `withdraw_rbf` → a `WithdrawUserRbf` pending info is created and `last_rbf_time_sec` is recorded on the original.
2. Protocol calls `cancel_withdraw` → a `WithdrawCancelRbf` pending info is created and `cancel_rbf_reserved` is set on the original.
3. Both RBF transactions are signed and broadcast to Bitcoin, spending the same UTXO(s).
4. Only one confirms; the other is a double-spend and is dropped by the network.
5. The losing pending info remains in NEAR contract storage indefinitely — it can never be verified on-chain, and no automatic cleanup path exists for it. Operator intervention is required to resolve the stale state.

This matches: **Medium — stuck bridge state requiring operator intervention**, and **bypass of bridge limits or policies** (`max_btc_tx_pending_sec` is the policy that separates the user-RBF window from the protocol-cancel window).

### Likelihood Explanation

Any user whose withdrawal has been pending longer than `max_btc_tx_pending_sec` can trigger this. The call is permissionless for the withdrawal owner, requires no special role, and needs only knowledge of their own `btc_pending_sign_id`. The window is open whenever the protocol is slow to call `cancel_withdraw` after the timeout.

### Recommendation

Add a symmetric upper-bound check in `internal_withdraw_rbf` (and the analogous `active_utxo_management_rbf`):

```rust
require!(
    nano_to_sec(env::block_timestamp()) - original_tx_btc_pending_info.create_time_sec
        <= self.internal_config().max_btc_tx_pending_sec,
    "User RBF window has closed; transaction may now be cancelled by protocol"
);
```

This mirrors the lower-bound guard in `internal_cancel_withdraw` and enforces the intended mutual exclusion between the user-RBF window and the protocol-cancel window.

### Proof of Concept

```
1. Alice initiates a withdrawal → WithdrawOriginal pending info created.
2. Alice signs via sign_btc_transaction → state moves to PendingVerify.
3. max_btc_tx_pending_sec seconds elapse without verify_withdraw being called.
4. Alice calls withdraw_rbf(original_id, higher_fee_output) → succeeds,
   creates WithdrawUserRbf pending info; original.cancel_rbf_reserved = None.
5. Protocol calls cancel_withdraw(original_id, cancel_output) → also succeeds
   (assert_not_canceled passes), creates WithdrawCancelRbf pending info,
   sets original.cancel_rbf_reserved.
6. Both RBF transactions are signed and broadcast to Bitcoin.
7. One confirms; the other is permanently invalid.
8. The losing NEAR pending info is stuck — verify_withdraw will always fail
   for it, and no unprivileged cleanup path exists.
``` [6](#0-5) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L30-34)
```rust
        require!(
            nano_to_sec(env::block_timestamp()) - original_tx_btc_pending_info.create_time_sec
                > self.internal_config().max_btc_tx_pending_sec,
            "Please wait user rbf"
        );
```

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L34-72)
```rust
    pub fn internal_withdraw_rbf(
        &mut self,
        account_id: &AccountId,
        original_btc_pending_verify_id: String,
        withdraw_rbf_psbt: PsbtWrapper,
        _predecessor_account_id: AccountId,
    ) -> String {
        let original_tx_btc_pending_info =
            self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
        original_tx_btc_pending_info.assert_not_canceled();
        original_tx_btc_pending_info.assert_withdraw_original_pending_verify_tx();

        let mut btc_pending_info = init_rbf_btc_pending_info(
            original_tx_btc_pending_info,
            PendingInfoState::WithdrawUserRbf(RbfState {
                stage: PendingInfoStage::PendingSign,
                original_tx_id: original_btc_pending_verify_id.clone(),
            }),
        );
        let (actual_received_amount, gas_fee) =
            self.check_withdraw_rbf_psbt_valid(original_tx_btc_pending_info, &withdraw_rbf_psbt);
        btc_pending_info.gas_fee = gas_fee;
        btc_pending_info.actual_received_amount = actual_received_amount;
        btc_pending_info.burn_amount = actual_received_amount + gas_fee;
        Self::check_withdraw_chain_specific(original_tx_btc_pending_info, gas_fee);

        self.internal_unwrap_mut_btc_pending_info(&original_btc_pending_verify_id)
            .update_max_gas_fee(gas_fee);
        self.set_rbf_pending_info(
            &original_btc_pending_verify_id,
            btc_pending_info,
            withdraw_rbf_psbt,
            false,
        )
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L295-297)
```rust
    pub fn assert_not_canceled(&self) {
        require!(self.get_cancel_rbf_reserved().is_none(), "already canceled");
    }
```
