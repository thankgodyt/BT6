### Title
When Bridge Is Paused, `claim_lost_found` and `withdraw_rbf` Are Also Paused, Temporarily Locking User Funds and Preventing Position Protection — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `satoshi-bridge` contract's emergency pause mechanism blocks all user-protective operations alongside operational ones. When paused, users with nBTC already held in the bridge's `lost_found` map cannot reclaim it via `claim_lost_found`, and users with pending withdrawal transactions cannot accelerate them via `withdraw_rbf`. Upon unpause, relayers can immediately finalize pending withdrawals before users have any opportunity to adjust gas fees, mirroring the external report's front-running pattern.

---

### Finding Description

The `satoshi-bridge` contract uses `near-plugins`' `Pausable` trait. Every user-facing write function is decorated with `#[pause(except(roles(Role::DAO)))]`, meaning a single `pa_pause_feature("ALL")` call by the `PauseManager` role halts all of them for non-DAO callers. [1](#0-0) 

The affected functions include:

| Function | File | Line |
|---|---|---|
| `ft_on_transfer` | `token_receiver.rs` | 22 |
| `sign_btc_transaction` | `chain_signatures.rs` | 20 |
| `verify_withdraw` / `verify_withdraw_v2` | `bridge.rs` | 217, 241 |
| `withdraw_rbf` | `bridge.rs` | 258 |
| `cancel_withdraw` | `bridge.rs` | 284 |
| `claim_lost_found` | `bridge.rs` | 450 |
| `request_refund` | `bridge.rs` | 509 |
| `execute_refund` | `bridge.rs` | 581 | [2](#0-1) [3](#0-2) 

**Path A — `claim_lost_found` locked:**

`lost_found` is populated when a `cancel_withdraw` RBF transaction is verified on-chain and the nBTC refund transfer back to the user fails (e.g., user's nBTC storage not registered). The nBTC is already bridge-held and owed to the user. If the bridge is paused at any point after this, `claim_lost_found` reverts with `"Method is paused"`, and the user has zero recourse until the bridge is unpaused. [4](#0-3) 

**Path B — `withdraw_rbf` locked + front-run on unpause:**

The withdrawal flow transfers nBTC to the bridge immediately in `ft_on_transfer` (bridge returns `U128(0)`, keeping all tokens). The BTC transaction is then signed and broadcast. If the bridge is paused while a withdrawal is in `PendingSign` or `PendingVerify` state:

1. `sign_btc_transaction` is paused — signing cannot complete.
2. `withdraw_rbf` is paused — user cannot increase the gas fee to accelerate a stuck transaction.
3. `cancel_withdraw` is paused **and** restricted to `Role::DAO, Role::Operator` — the user has no self-service cancellation path. [5](#0-4) [6](#0-5) 

When the bridge is unpaused, a relayer bot can immediately call `sign_btc_transaction` → broadcast → `verify_withdraw` in the same block window, finalizing the withdrawal at the original (potentially low) gas fee before the user can call `withdraw_rbf` to adjust it. The user's nBTC is burned at the original fee with no opportunity to intervene.

---

### Impact Explanation

- **`claim_lost_found` paused**: nBTC that is already owed to users (sitting in `data.lost_found`) is temporarily locked with no user-accessible recovery path. This is a direct temporary locking of bridged funds.
- **`withdraw_rbf` paused + front-run**: Users cannot protect their pending withdrawal positions during a pause. On unpause, relayers can race to finalize at the original gas fee, denying users the ability to adjust. This mirrors the external report's "repayments paused → front-run on unpause" pattern.

Impact classification: **Medium** — attacker-triggered (via legitimate pause) temporary locking of bridged funds; stuck bridge state requiring operator intervention.

---

### Likelihood Explanation

The bridge has a defined `PauseManager` role and the pause mechanism is explicitly tested and intended for emergency use. [7](#0-6) 

Any emergency pause — even a legitimate one — triggers this condition for all users who have nBTC in `lost_found` or pending withdrawals at that moment. The likelihood is **Medium**: pauses are infrequent but the impact on affected users is immediate and unavoidable.

---

### Recommendation

Remove `claim_lost_found` from the pause scope entirely — it only transfers nBTC already owed to the caller and poses no security risk when the bridge is paused:

```rust
// Before:
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn claim_lost_found(&mut self) -> Promise { ... }

// After:
#[payable]
pub fn claim_lost_found(&mut self) -> Promise { ... }
```

Similarly, allow `withdraw_rbf` to remain callable when paused (analogous to the external report's recommendation to keep repayments open), so users can protect their pending positions even during an emergency pause. At minimum, document that `cancel_withdraw` should be called by the operator for all affected users immediately upon pausing.

---

### Proof of Concept

**Path A (`claim_lost_found` locked):**

1. Alice initiates withdrawal: `nbtc.ft_transfer_call(bridge, 100_000, WithdrawMsg{...})` — nBTC transferred to bridge.
2. DAO/Operator calls `cancel_withdraw(pending_id, output)` — cancel RBF is signed and verified.
3. `verify_withdraw` callback attempts `internal_transfer_nbtc(&alice, refund)` — transfer fails (Alice not registered in nBTC), nBTC goes to `data.lost_found[alice]`.
4. PauseManager calls `pa_pause_feature("ALL")`.
5. Alice calls `claim_lost_found()` → **panics: "Method is paused"**.
6. Alice's nBTC is locked until the bridge is unpaused. [2](#0-1) 

**Path B (`withdraw_rbf` front-run on unpause):**

1. Alice initiates withdrawal at gas fee `10_000 sat`.
2. BTC mempool congestion spikes; transaction is stuck.
3. PauseManager calls `pa_pause_feature("ALL")`.
4. Alice attempts `withdraw_rbf(pending_id, new_output_with_higher_fee)` → **panics: "Method is paused"**.
5. PauseManager calls `pa_unpause_feature("ALL")`.
6. Relayer bot (monitoring mempool) immediately calls `sign_btc_transaction(pending_id, 0, key_version)` in the same block.
7. Alice's withdrawal is finalized at the original low gas fee; she had no window to call `withdraw_rbf`. [3](#0-2) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L160-163)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
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

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L139-142)
```rust
            if refund > 0 {
                self.internal_transfer_nbtc(&btc_pending_info.account_id, refund)
                    .detach();
            }
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

**File:** contracts/satoshi-bridge/tests/test_satoshi_bridge.rs (L64-74)
```rust
    check!(print context.bridge_pa_pause_feature("alice", "ALL"));
    check!(
        context.verify_withdraw(
            "relayer",
            "",
            "0000000000000c3f818b0b6374c609dd8e548a0a9e61065e942cd466c426e00d".to_string(),
            1,
            vec![]
        ),
        "Method is paused"
    );
```

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-43)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```
