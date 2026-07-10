### Title
`acc_protocol_fee_for_gas` Accumulates Protocol Fees With No Withdrawal Mechanism, Permanently Locking DAO Revenue - (File: contracts/satoshi-bridge/src/nbtc/burn.rs)

### Summary
The `acc_protocol_fee_for_gas` counter in `ContractData` accumulates protocol fees during cancel-withdraw RBF finalization and active UTXO management, but no function exists to withdraw or disburse these funds. In the cancel-withdraw RBF path specifically, reserved protocol fees that should flow to `cur_available_protocol_fee` (claimable by the DAO) are instead permanently locked in `acc_protocol_fee_for_gas`.

### Finding Description
`ContractData` maintains five fee-related counters. Four of them participate in a complete lifecycle: `acc_collected_protocol_fee`, `cur_available_protocol_fee`, `acc_claimed_protocol_fee`, and `cur_reserved_protocol_fee`. The fifth, `acc_protocol_fee_for_gas`, is only ever incremented and is never decremented or disbursed. [1](#0-0) 

The only DAO withdrawal function, `withdraw_protocol_fee`, exclusively operates on `cur_available_protocol_fee` and `acc_claimed_protocol_fee`: [2](#0-1) 

In `verify_withdraw_burn_callback`, when a cancel-withdraw RBF is finalized, the `cancel_rbf_reserved` protocol fee is routed to `acc_protocol_fee_for_gas` instead of `cur_available_protocol_fee`: [3](#0-2) 

The non-cancel RBF branch (same function, lines 127–133) correctly routes the equivalent reserved fee to `cur_available_protocol_fee`. This asymmetry means cancel-withdraw RBF protocol fees are permanently inaccessible to the DAO.

Similarly, in `verify_active_utxo_management_burn_callback`, the `burn_amount` (the actual BTC gas cost paid to miners) is added to `acc_protocol_fee_for_gas`: [4](#0-3) 

`acc_protocol_fee_for_gas` is only ever read in the `get_metadata()` view function and is never decremented anywhere in the codebase: [5](#0-4) 

### Impact Explanation
Protocol fees collected during cancel-withdraw RBF operations are permanently locked in `acc_protocol_fee_for_gas` with no withdrawal path. The DAO cannot recover these satoshis via `withdraw_protocol_fee` because that function only reads `cur_available_protocol_fee`. Every cancel-withdraw RBF finalization permanently removes protocol revenue from DAO control. This is a permanent, irreversible accounting loss of bridge protocol revenue — matching the **Medium** impact category of harmful smart-contract behavior causing permanent loss of protocol funds without direct user theft.

### Likelihood Explanation
Cancel-withdraw RBF is a normal, documented bridge operation available to any user who has initiated a withdrawal. Any user can trigger a cancel-withdraw RBF by calling the RBF cancellation flow. Each such operation that reaches `verify_withdraw_burn_callback` with `is_cancel_withdraw_rbf() == true` will permanently lock the `cancel_rbf_reserved` protocol fee. This is a reachable, unprivileged path.

### Recommendation
Add a `withdraw_protocol_fee_for_gas` management function (gated by `Role::DAO`) that allows the DAO to claim accumulated `acc_protocol_fee_for_gas` funds, mirroring the existing `withdraw_protocol_fee` pattern. Alternatively, route `cancel_rbf_reserved` to `cur_available_protocol_fee` in the cancel-withdraw RBF branch (consistent with the non-cancel branch), and use `acc_protocol_fee_for_gas` only as a pure accounting record for already-spent BTC gas costs.

### Proof of Concept
1. User initiates a withdrawal via `ft_transfer_call` with a `WithdrawMsg`.
2. The withdrawal transaction is signed and broadcast to Bitcoin.
3. User (or protocol) initiates a cancel-withdraw RBF, creating a new pending transaction that sends BTC back to the bridge's change address.
4. The cancel RBF transaction is confirmed on Bitcoin.
5. Relayer calls `verify_withdraw` on the cancel RBF transaction.
6. `verify_withdraw_burn_callback` is invoked. `btc_pending_info.is_cancel_withdraw_rbf()` returns `true`.
7. `cancel_rbf_reserved > 0` (the protocol fee reserved for the cancel transaction).
8. `self.data_mut().acc_protocol_fee_for_gas += cancel_rbf_reserved` executes — these satoshis are now permanently locked.
9. DAO calls `withdraw_protocol_fee` — it reads only `cur_available_protocol_fee`, which does not include the locked amount. The `cancel_rbf_reserved` satoshis are permanently inaccessible.

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L141-145)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L21-29)
```rust
    pub fn withdraw_protocol_fee(&mut self, amount: Option<U128>) -> Promise {
        assert_one_yocto();
        let total_protocol_fee = self.data().cur_available_protocol_fee;
        let amount = amount.map_or(total_protocol_fee, |v| v.0);
        require!(amount > 0 && amount <= total_protocol_fee, "Invalid amount");
        self.data_mut().cur_available_protocol_fee -= amount;
        self.data_mut().acc_claimed_protocol_fee += amount;
        self.internal_withdraw_protocol_fee(amount)
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L109-119)
```rust
                if let Some(U128(cancel_rbf_reserved)) =
                    original_tx_btc_pending_info.get_cancel_rbf_reserved()
                {
                    if cancel_rbf_reserved > 0 {
                        self.data_mut().cur_reserved_protocol_fee -= cancel_rbf_reserved;
                        if btc_pending_info.is_cancel_withdraw_rbf() {
                            self.data_mut().acc_protocol_fee_for_gas += cancel_rbf_reserved;
                        } else {
                            self.data_mut().cur_available_protocol_fee += cancel_rbf_reserved;
                        }
                    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L199-214)
```rust
                let reserved_protocol_fee = original_tx_btc_pending_info.get_max_gas_fee();
                let unused_reserved_protocol_fee =
                    reserved_protocol_fee - btc_pending_info.burn_amount;
                self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
                self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
                self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
            } else {
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(&tx_id);
                let reserved_protocol_fee = btc_pending_info.get_max_gas_fee();
                let unused_reserved_protocol_fee =
                    reserved_protocol_fee - btc_pending_info.burn_amount;
                self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
                self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
                self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L77-77)
```rust
            acc_protocol_fee_for_gas: root_state.acc_protocol_fee_for_gas,
```
