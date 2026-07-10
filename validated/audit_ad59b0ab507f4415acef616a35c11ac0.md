### Title
Bridge Pause Uniformly Blocks In-Flight Withdrawal Completion, Permanently Locking User nBTC in Bridge Contract - (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

When the bridge is paused, `sign_btc_transaction`, `verify_withdraw`/`verify_withdraw_v2`, `withdraw_rbf`, and `claim_lost_found` are all blocked by the same `#[pause(except(roles(Role::DAO)))]` guard that blocks new withdrawal initiations. Users who have already transferred their nBTC to the bridge (step 1 of the withdrawal flow) cannot complete or recover their in-flight withdrawal while the bridge is paused. Their nBTC is stuck in the bridge contract with no user-accessible recovery path.

---

### Finding Description

The withdrawal flow in this bridge is multi-step:

1. User calls `nbtc.ft_transfer_call(bridge, amount, WithdrawMsg)` — nBTC tokens are **transferred to the bridge contract** (not burned yet).
2. Bridge's `ft_on_transfer` is invoked, creates a `BTCPendingInfo` record, and returns `0` (keeps the tokens).
3. `sign_btc_transaction` is called to obtain an MPC signature.
4. The signed BTC transaction is broadcast to Bitcoin.
5. Relayer calls `verify_withdraw`/`verify_withdraw_v2` to prove on-chain inclusion; bridge burns the nBTC.

Every function needed to advance or recover an in-flight withdrawal carries the identical pause guard:

- `ft_on_transfer` — `#[pause(except(roles(Role::DAO)))]` (initiates withdrawal)
- `sign_btc_transaction` — `#[pause(except(roles(Role::DAO)))]` (completes MPC signing)
- `verify_withdraw` / `verify_withdraw_v2` — `#[pause(except(roles(Role::DAO)))]` (finalizes and burns)
- `withdraw_rbf` — `#[pause(except(roles(Role::DAO)))]` (accelerates stuck tx)
- `claim_lost_found` — `#[pause(except(roles(Role::DAO)))]` (recovers nBTC from failed cancel)

If the bridge is paused **after** step 2 has completed (BTCPendingInfo exists, nBTC is in the bridge), the user has no way to:
- advance the signing (`sign_btc_transaction` blocked),
- finalize the withdrawal (`verify_withdraw` blocked),
- accelerate a stuck transaction (`withdraw_rbf` blocked), or
- recover nBTC from lost & found (`claim_lost_found` blocked).

The pause check does not distinguish between **initiating** a new withdrawal (where blocking is appropriate) and **completing** an already-initiated one (where blocking traps user funds). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

The CLAUDE.md security invariant explicitly states: *"Withdraw tokens already transferred: By the time `burn()` is called, tokens are in bridge balance via `ft_transfer`"* — confirming that after step 2, the user's nBTC is already inside the bridge and the user has no independent custody of it. [7](#0-6) 

---

### Impact Explanation

When the bridge is paused (e.g., due to an emergency), any user who has already completed step 1–2 of the withdrawal flow has their nBTC locked inside the bridge contract with no user-accessible recovery mechanism. The tokens cannot be burned (withdrawal not finalized), cannot be returned (no refund path for in-flight withdrawals), and cannot be claimed from lost & found. The only resolution is for the DAO to unpause the bridge. This constitutes a stuck bridge state requiring operator intervention, matching the **Medium** impact category: *"Harmful smart-contract behavior without direct funds theft, including … stuck bridge state requiring operator intervention."*

---

### Likelihood Explanation

The bridge has a `PauseManager` role that can pause individual features or all features via `pa_pause_feature("ALL")`. The test suite explicitly exercises this path. Any emergency pause — which is the exact scenario where users most need to recover their funds — triggers this condition for all users with in-flight withdrawals at that moment. [8](#0-7) 

---

### Recommendation

Distinguish between **initiating** a new withdrawal and **completing** an already-initiated one:

- Keep `#[pause(except(roles(Role::DAO)))]` on `ft_on_transfer` — blocking new withdrawals during a pause is correct.
- Remove or relax the pause guard on `sign_btc_transaction`, `verify_withdraw`, `verify_withdraw_v2`, `withdraw_rbf`, and `claim_lost_found` so that users can always complete or recover in-flight withdrawals regardless of pause state. At minimum, add the user's own account as an exempt role for their own pending transactions, or check whether a `BTCPendingInfo` already exists before enforcing the pause.

---

### Proof of Concept

1. Alice calls `nbtc.ft_transfer_call(bridge, 100_000, WithdrawMsg{...})`.
2. Bridge's `ft_on_transfer` executes (not yet paused), creates `BTCPendingInfo`, keeps Alice's 100,000 nBTC.
3. A `PauseManager` calls `pa_pause_feature("ALL")` — bridge is now paused.
4. Alice calls `sign_btc_transaction(btc_pending_sign_id, 0, 0)` → **panics: "Method is paused"**.
5. Relayer calls `verify_withdraw(tx_id, ...)` → **panics: "Method is paused"**.
6. Alice calls `claim_lost_found()` → **panics: "Method is paused"**.
7. Alice's 100,000 nBTC remain locked in the bridge contract indefinitely until the DAO unpauses. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L22-23)
```rust
    #[pause(except(roles(Role::DAO)))]
    fn ft_on_transfer(
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L40-67)
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
    }
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L216-217)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L240-241)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-259)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
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

**File:** CLAUDE.md (L62-65)
```markdown
- **Withdraw tokens already transferred:** By the time `burn()` is called, tokens are in bridge balance via `ft_transfer`
- **burn_account_id is for events only:** Actual burn happens from bridge balance, not from burn_account_id
- **ft_on_transfer return value:** `0` = keep all tokens, `amount` = refund amount
- Only burn after BTC tx is verified on-chain
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
