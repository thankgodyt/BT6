The key code paths are now fully traced. Let me verify the exact state transitions and the `rbf_txs` removal timing.

### Title
Unprivileged `clear_invalid_pending_verify_rbf` Races In-Flight RBF Callback to Permanently Lock User nBTC — (`contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`clear_invalid_pending_verify_rbf` is callable by any account and removes an RBF `BTCPendingInfo` entry whenever `rbf_txs` no longer contains the `original_tx_id` key. Because the original tx's `rbf_txs` entry is erased atomically when the original's own `verify_withdraw_burn_callback` succeeds, an attacker can race this public call against an already-dispatched `verify_withdraw_v2` callback for the RBF tx. The callback then panics on `internal_unwrap_btc_pending_info`, leaving the user's nBTC permanently locked in the bridge with no recovery path.

---

### Finding Description

**Entrypoint — unprivileged public function:**

`clear_invalid_pending_verify_rbf` carries only a `#[pause]` guard; any account can call it when the contract is not paused. [1](#0-0) 

**Clearing logic — `internal_clear_invalid_pending_verify_rbf`:**

```
1. internal_remove_btc_pending_info(&btc_pending_id)   // removes entry unconditionally first
2. assert_pending_verify()                              // stage check on the already-removed copy
3. get_original_tx_id().expect(...)                    // must be an RBF tx
4. require!(!rbf_txs.contains_key(original_tx_id))    // passes once original is verified
``` [2](#0-1) 

**When does `rbf_txs` lose the original's key?**

`verify_withdraw_burn_callback` for the original tx (the `else` branch — no `original_tx_id`) calls `rbf_txs.remove(&tx_id)` and then `internal_remove_btc_pending_info(&tx_id)` in the same atomic transaction. [3](#0-2) 

**Guard in `internal_verify_withdraw_entry` that prevents late calls:**

```rust
if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
    require!(
        self.check_btc_pending_info_exists(original_tx_id),
        "original tx already verified"
    );
}
``` [4](#0-3) 

This guard only runs at **dispatch time**. Once the cross-contract call to the light client is in flight, no re-check occurs before the callback executes.

**Callback that panics:**

```rust
pub fn internal_verify_withdraw_callback(&mut self, tx_id: String) -> PromiseOrValue<bool> {
    ...
    self.internal_unwrap_btc_pending_info(&tx_id)   // panics if entry was removed
        .assert_pending_verify();
    ...
}
``` [5](#0-4) 

`internal_unwrap_btc_pending_info` calls `.expect("BTC pending info not exist")`, which panics unconditionally when the entry is absent. [6](#0-5) 

---

### Impact Explanation

When `internal_verify_withdraw_callback` panics, NEAR reverts all state changes within that callback. However, the user's nBTC was transferred to the bridge in an earlier, already-committed transaction (the withdrawal initiation). The RBF `BTCPendingInfo` entry no longer exists (removed by the attacker), so:

- The bridge holds the user's nBTC with no pending info to track it.
- No `lost_found` entry is created (that path is only populated by explicit operator/DAO actions, not by a panicking callback).
- `claim_lost_found` cannot help because nothing was written to `lost_found`.
- The funds are permanently locked.

This matches **Critical — significant permanent locking of user funds**.

---

### Likelihood Explanation

NEAR's async cross-contract call model guarantees a window of one or more blocks between the dispatch of `verify_transaction_inclusion_promise` and the execution of `internal_verify_withdraw_callback`. During that window, any number of other transactions can execute. An attacker monitoring the chain can:

1. Observe the relayer's `verify_withdraw_v2` call for the RBF tx (public mempool / indexer).
2. Observe the original tx's `verify_withdraw_burn_callback` completing (on-chain event).
3. Immediately submit `clear_invalid_pending_verify_rbf(rbf_tx_id)` — no privilege required, no deposit required.

The attack requires no leaked keys, no operator collusion, and no BTC-layer majority. It is a straightforward NEAR transaction ordering attack executable by any account.

---

### Recommendation

**Option A (preferred):** In `internal_clear_invalid_pending_verify_rbf`, check that no in-flight verification exists for the RBF tx before removing it. The simplest proxy is to check that the RBF pending info's stage is `PendingVerify` AND that the original's `btc_pending_infos` entry is also absent (i.e., the original was fully cleaned up). However, the cleanest fix is to **not remove the entry before validating**; instead, validate first and only then remove:

```rust
pub fn internal_clear_invalid_pending_verify_rbf(&mut self, btc_pending_id: String) {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_id); // borrow, don't remove
    btc_pending_info.assert_pending_verify();
    let original_tx_id = btc_pending_info.get_original_tx_id().expect("Not rbf transaction");
    require!(
        !self.data().rbf_txs.contains_key(original_tx_id),
        "Not invalid pending verify rbf"
    );
    // Only remove after all checks pass — same as before, but this alone doesn't fix the race.
    self.internal_remove_btc_pending_info(&btc_pending_id);
}
```

That alone does not close the race. The real fix is to **add an access control gate** (e.g., `#[access_control_any(roles(Role::DAO, Role::Operator))]`) matching the pattern used by `cancel_withdraw` and `cancel_active_utxo_management`, so that only trusted operators can invoke cleanup.

**Option B:** In `internal_verify_withdraw_callback`, replace the hard `expect` with a graceful check: if the pending info is absent, treat it as a no-op (or revert to `PendingVerify` via the burn-failure path). This prevents the panic but does not prevent the state corruption.

**Option C (defense-in-depth):** Track an "in-flight verification" flag on the `BTCPendingInfo` (e.g., a `PendingBurnInFlight` stage) set at dispatch time and cleared by the callback, and reject `clear_invalid_pending_verify_rbf` for entries in that stage.

---

### Proof of Concept

```
Block N:
  relayer → verify_withdraw_v2(rbf_tx_id, proof)
    internal_verify_withdraw_entry:
      - unwrap RBF pending info ✓ (exists, PendingVerify)
      - check_btc_pending_info_exists(original_tx_id) ✓ (original still exists)
      - dispatch verify_transaction_inclusion_promise → callback scheduled

Block N+1:
  relayer → verify_withdraw_v2(original_tx_id, proof)  [or its callback fires]
    verify_withdraw_burn_callback (original, else branch):
      - rbf_txs.remove(&original_tx_id)          // rbf_txs no longer has original's key
      - internal_remove_btc_pending_info(original_tx_id)

Block N+1 (same block, later tx) or Block N+2:
  attacker → clear_invalid_pending_verify_rbf(rbf_tx_id)
    internal_clear_invalid_pending_verify_rbf:
      - internal_remove_btc_pending_info(rbf_tx_id) ✓ (exists, removed)
      - assert_pending_verify() ✓ (still PendingVerify, callback not yet fired)
      - get_original_tx_id() → original_tx_id ✓
      - !rbf_txs.contains_key(original_tx_id) → TRUE ✓
      → RBF pending info deleted

Block N+2 (callback fires):
  internal_verify_withdraw_callback(rbf_tx_id):
    - internal_unwrap_btc_pending_info(rbf_tx_id)
      → .expect("BTC pending info not exist") → PANIC

Result: user's nBTC remains in bridge balance, no pending info, no lost_found entry → permanently locked.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L436-439)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_id: String) {
        self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
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

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L121-143)
```rust
            } else {
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(&tx_id);
                self.data_mut().rbf_txs.remove(&tx_id);

                if let Some(U128(cancel_rbf_reserved)) = btc_pending_info.get_cancel_rbf_reserved()
                {
                    if cancel_rbf_reserved > 0 {
                        self.data_mut().cur_reserved_protocol_fee -= cancel_rbf_reserved;
                        self.data_mut().cur_available_protocol_fee += cancel_rbf_reserved;
                    }
                }
            }
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
            if refund > 0 {
                self.internal_transfer_nbtc(&btc_pending_info.account_id, refund)
                    .detach();
            }
            self.internal_remove_btc_pending_info(&tx_id);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L47-51)
```rust
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            require!(
                self.check_btc_pending_info_exists(original_tx_id),
                "original tx already verified"
            );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L71-82)
```rust
    pub fn internal_verify_withdraw_callback(&mut self, tx_id: String) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        self.internal_unwrap_btc_pending_info(&tx_id)
            .assert_pending_verify();
        self.internal_unwrap_mut_btc_pending_info(&tx_id)
            .to_pending_burn_stage();
        self.verify_withdraw_burn_promise(tx_id).into()
    }
```
