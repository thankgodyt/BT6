### Title
Unprivileged `clear_invalid_pending_verify_rbf` Races In-Flight RBF Callback, Permanently Locking User nBTC — (`contracts/satoshi-bridge/src/btc_pending_info.rs`)

---

### Summary

`clear_invalid_pending_verify_rbf` is callable by any account and unconditionally removes an RBF pending info entry if `rbf_txs` no longer contains the `original_tx_id`. Because NEAR cross-contract calls are asynchronous, an attacker can insert this call between the moment the original tx is verified (which removes its `rbf_txs` entry) and the moment the RBF's `internal_verify_withdraw_callback` fires. The callback then panics on `internal_unwrap_btc_pending_info`, the burn never executes, and the user's nBTC is permanently locked in the bridge with no recovery path.

---

### Finding Description

**Entry point (attacker-controlled, unprivileged):**

`clear_invalid_pending_verify_rbf` (bridge.rs line 437) has no role gate — only the global pause check. [1](#0-0) 

**Internal implementation:** [2](#0-1) 

The function:
1. **Removes** the pending info from storage first (line 404).
2. Asserts it is in `PendingVerify` state (line 405).
3. Checks `!rbf_txs.contains_key(original_tx_id)` (line 409-412).

After the original tx is verified via `verify_withdraw_burn_callback`, the original's `rbf_txs` entry is removed: [3](#0-2) 

and the original's pending info is removed: [4](#0-3) 

At this point, the RBF's pending info is **still in storage** (in `PendingVerify` state), and `rbf_txs` no longer contains the `original_tx_id` key. Both conditions in `internal_clear_invalid_pending_verify_rbf` pass, so the attacker's call succeeds and removes the RBF pending info.

**The race window:**

`verify_withdraw_v2` for the RBF tx dispatches a cross-contract call to the light client, then schedules `internal_verify_withdraw_callback`: [5](#0-4) 

Between the dispatch and the callback, other transactions execute. The attacker inserts `clear_invalid_pending_verify_rbf` here.

**The callback panic:**

When `internal_verify_withdraw_callback` fires, it calls: [6](#0-5) 

`internal_unwrap_btc_pending_info` calls `.expect("BTC pending info not exist")`: [7](#0-6) 

This panics. The callback transaction reverts. `verify_withdraw_burn_promise` is never called. The nBTC burn never executes.

**Guard that should block this — but doesn't:**

`internal_verify_withdraw_entry` does check that the original tx still exists before dispatching: [8](#0-7) 

But this check is only at dispatch time. There is no equivalent guard in `internal_clear_invalid_pending_verify_rbf` to detect that the RBF's callback is in-flight. There is no "in-flight" flag or lock on the pending info.

**Why the nBTC is permanently locked:**

The user transferred nBTC to the bridge via `ft_transfer_call` when initiating the withdrawal. The bridge holds it until `verify_withdraw_burn_callback` burns it. Since the callback panics before the burn, the nBTC remains in the bridge's balance. `claim_lost_found` only covers amounts explicitly placed in the `lost_found` map — this panic path does not populate it. [9](#0-8) 

---

### Impact Explanation

The user's nBTC is permanently locked in the bridge contract with no recovery path. The BTC transaction (the RBF) was already broadcast and confirmed on-chain. The user loses their nBTC while the BTC has left the bridge. This is a **critical permanent loss of user funds**.

---

### Likelihood Explanation

- `clear_invalid_pending_verify_rbf` requires zero privileges and zero attached deposit.
- The race window spans at least one NEAR block (~1 second) — the time between the original tx's `verify_withdraw_burn_callback` completing and the RBF's `internal_verify_withdraw_callback` firing.
- An attacker can monitor NEAR events (e.g., `VerifyWithdrawDetails` emitted by the original tx's burn callback) and immediately submit the attack transaction.
- The attack is cheap (no stake, no special role) and deterministic once the window opens.

---

### Recommendation

Add a guard in `internal_clear_invalid_pending_verify_rbf` that checks the RBF pending info's stage is still `PendingVerify` **and** that no in-flight callback exists. The simplest fix is to introduce a `PendingBurn` stage transition at the start of `internal_verify_withdraw_callback` (before the cross-contract burn call) and reject `clear_invalid_pending_verify_rbf` for entries in `PendingBurn` state. Alternatively, check that the RBF tx id is not currently referenced in any active promise chain, or simply disallow `clear_invalid_pending_verify_rbf` for any RBF whose original has been verified within the same block/epoch.

---

### Proof of Concept

```
1. Alice initiates withdrawal → original tx created (PendingSign → PendingVerify).
2. Operator creates RBF → RBF tx created (PendingSign → PendingVerify),
   rbf_txs[original_tx_id] = {rbf_tx_id}.
3. Relayer calls verify_withdraw_v2(rbf_tx_id, proof).
   - internal_verify_withdraw_entry: original exists ✓, dispatches cross-contract call.
   - internal_verify_withdraw_callback is now pending (in-flight).
4. Relayer calls verify_withdraw_v2(original_tx_id, proof) → completes fully:
   - verify_withdraw_burn_callback: rbf_txs.remove(original_tx_id),
     internal_remove_btc_pending_info(original_tx_id).
5. Attacker calls clear_invalid_pending_verify_rbf(rbf_tx_id):
   - internal_remove_btc_pending_info(rbf_tx_id) → succeeds (entry exists, PendingVerify).
   - !rbf_txs.contains_key(original_tx_id) → true (removed in step 4) → no panic.
   - RBF pending info is now gone from storage.
6. internal_verify_withdraw_callback(rbf_tx_id) fires:
   - internal_unwrap_btc_pending_info(rbf_tx_id) → expect() panics.
   - Callback reverts. Burn never executes.
7. Alice's nBTC remains in bridge balance. No claim_lost_found entry. Funds permanently locked.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L436-439)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_id: String) {
        self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L451-460)
```rust
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L376-382)
```rust
    pub fn internal_unwrap_btc_pending_info(&self, btc_pending_id: &String) -> &BTCPendingInfo {
        self.data()
            .btc_pending_infos
            .get(btc_pending_id)
            .map(Into::into)
            .expect("BTC pending info not exist")
    }
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L403-413)
```rust
    pub fn internal_clear_invalid_pending_verify_rbf(&mut self, btc_pending_id: String) {
        let btc_pending_info = self.internal_remove_btc_pending_info(&btc_pending_id);
        btc_pending_info.assert_pending_verify();
        let original_tx_id = btc_pending_info
            .get_original_tx_id()
            .expect("Not rbf transaction");
        require!(
            !self.data().rbf_txs.contains_key(original_tx_id),
            "Not invalid pending verify rbf"
        );
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L121-125)
```rust
            } else {
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(&tx_id);
                self.data_mut().rbf_txs.remove(&tx_id);
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L143-143)
```rust
            self.internal_remove_btc_pending_info(&tx_id);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L30-34)
```rust
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_VERIFY_CANCEL_WITHDRAW_CALL_BACK)
                .internal_verify_withdraw_callback(tx_id),
        )
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L47-51)
```rust
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            require!(
                self.check_btc_pending_info_exists(original_tx_id),
                "original tx already verified"
            );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L77-81)
```rust
        self.internal_unwrap_btc_pending_info(&tx_id)
            .assert_pending_verify();
        self.internal_unwrap_mut_btc_pending_info(&tx_id)
            .to_pending_burn_stage();
        self.verify_withdraw_burn_promise(tx_id).into()
```
