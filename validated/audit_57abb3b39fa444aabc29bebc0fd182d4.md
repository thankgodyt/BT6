The code path is concrete and traceable. Let me confirm the key mechanics before rendering a verdict.

**Trace of the attack path:**

**Step 1 — Attacker calls `execute_refund`:**

`execute_refund` has no ownership check — any caller who passes the timelock check can call it. [1](#0-0) 

Inside `internal_execute_refund`, `caller = env::predecessor_account_id()` (the attacker), and the PSBT is built purely from the `RefundRequest` data — inputs/outputs are identical regardless of who calls. [2](#0-1) 

**Step 2 — `btc_pending_id` is deterministic:**

`get_pending_id()` computes the Bitcoin txid from the unsigned transaction. Since inputs (deposit UTXO outpoint) and outputs (refund address, amount) are fixed by the `RefundRequest`, the txid is **identical regardless of who calls `execute_refund`**. [3](#0-2) 

**Step 3 — `BTCPendingInfo` is inserted under the attacker's account:**

`finalize_refund_with_psbt` inserts the `BTCPendingInfo` keyed by the deterministic txid, with `account_id: caller.clone()` (the attacker). The `require!` at line 366 panics with `"pending info already exist"` if the key is already present. [4](#0-3) 

**Step 4 — UTXO is permanently marked:**

`verified_deposit_utxo` is written with the `utxo_storage_key`. There is no API to remove entries from this set. [5](#0-4) 

**Step 5 — Victim's retry fails:**

`load_refund_request_for_execute` allows re-execution when `executed == true` (the `|| refund_request.executed` branch), so the timelock/deposit check passes. But `finalize_refund_with_psbt` then hits the `"pending info already exist"` panic because the attacker's entry is still in `btc_pending_infos`. [6](#0-5) 

**Step 6 — Recovery paths are insufficient:**

- `reject_refund` (DAO/Operator only) removes the `refund_requests` entry but does **not** clear `verified_deposit_utxo`. [7](#0-6) 
- `remove_refund_pending_tx_id` (trusted relayer only) requires the refund request to already be gone (`"refund request still active"` guard). [8](#0-7) 
- After both are called, `verified_deposit_utxo` still contains the key, so a new `request_refund` for the same UTXO fails with `"UTXO already verified via deposit"`. [9](#0-8) 
- `verify_deposit` is also blocked by the same set (confirmed by `test_refund_then_deposit_fails`).

The existing test `test_refund_execute_twice_different_account` covers the case where a **privileged** account (DAO) calls first and a non-privileged account tries second — treating the duplicate rejection as a protection. But it does **not** cover the adversarial case where an unprivileged attacker front-runs the legitimate requester. [10](#0-9) 

---

### Title
Unprivileged front-running of `execute_refund` permanently locks victim's deposit UTXO — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
Any unprivileged account can call `execute_refund` for any refund request once the timelock has elapsed. Because the Bitcoin refund txid is deterministic (derived solely from the deposit UTXO and refund address, not the caller), the first caller claims the `BTCPendingInfo` slot. If an attacker front-runs the legitimate requester and then refuses to sign, the victim's retry is rejected with `"pending info already exist"`. Operator intervention (`reject_refund` + `remove_refund_pending_tx_id`) can remove the stale state, but `verified_deposit_utxo` is never cleared, permanently blocking both a new `request_refund` and `verify_deposit` for the same UTXO.

### Finding Description
`execute_refund` has no ownership check — it accepts any caller who passes the timelock. Inside `internal_execute_refund`, `caller = env::predecessor_account_id()` is passed to `finalize_refund_with_psbt`, which:

1. Computes `btc_pending_id` from `psbt.get_pending_id()` — a deterministic Bitcoin txid that depends only on the deposit UTXO outpoint and refund output, not the caller.
2. Inserts a `BTCPendingInfo` with `account_id: caller` under that txid.
3. Inserts `utxo_storage_key` into `verified_deposit_utxo`.
4. Sets `refund_request.executed = true`.

When the victim subsequently calls `execute_refund`, `load_refund_request_for_execute` passes (because `executed == true` bypasses the `verified_deposit_utxo` guard), but `finalize_refund_with_psbt` panics at the `btc_pending_infos.insert(...).is_none()` check because the attacker's entry already occupies the same txid key.

The attacker's `BTCPendingInfo` is in `PendingSign` state owned by the attacker. Only the attacker can call `sign_btc_transaction` for it. If the attacker refuses, the pending info is never advanced to `PendingVerify`, and `verify_refund_finalize` can never be called. Meanwhile, `verified_deposit_utxo` permanently blocks both `request_refund` and `verify_deposit` for the same UTXO.

### Impact Explanation
The victim's deposit UTXO is stuck: the bridge will never mint nBTC for it (deposit path blocked) and will never return the BTC (refund path blocked). The BTC remains unspent on Bitcoin but is inaccessible through the bridge. Full recovery requires privileged operator action (`reject_refund` + `remove_refund_pending_tx_id`) followed by a protocol-level fix to clear `verified_deposit_utxo` — there is no public API for the latter, making the lock effectively permanent without a contract upgrade.

### Likelihood Explanation
The attack requires only: (a) a refund request with `executed == false` and the timelock elapsed, (b) the attacker having zero existing pending sign txs (the default limit is 1), and (c) the storage deposit for `execute_refund`. All three are easily satisfied. The attacker can monitor the NEAR blockchain for timelock expiry and front-run with a single transaction. No privileged access, leaked keys, or off-chain coordination is needed.

### Recommendation
Add an ownership check to `execute_refund`: only the original requester (the account that called `request_refund`) or a privileged role (DAO/RefundOperator) should be allowed to execute a refund. Store the requester's `AccountId` in `RefundRequest` at `request_refund_callback` time and enforce it in `resolve_execute_refund_timelock` or `load_refund_request_for_execute`.

Alternatively, if permissionless execution is desired, the `BTCPendingInfo` ownership should be set to the original requester (stored in `RefundRequest`), not `env::predecessor_account_id()`, so the victim retains signing rights regardless of who calls `execute_refund`.

Additionally, `verified_deposit_utxo` should be cleared when a refund is rejected or its pending info is removed without finalization, to restore the victim's ability to re-request a refund.

### Proof of Concept
```
1. Alice calls request_refund(deposit_msg, ...) → RefundRequest stored with executed=false
2. Timelock elapses
3. Attacker (bob) calls execute_refund(utxo_storage_key):
   - BTCPendingInfo inserted: {account_id: bob, btc_pending_id: <txid>, state: PendingSign}
   - verified_deposit_utxo.insert(utxo_storage_key)
   - refund_request.executed = true
4. Bob does NOT call sign_btc_transaction
5. Alice calls execute_refund(utxo_storage_key):
   - load_refund_request_for_execute passes (executed==true bypasses verified_deposit_utxo guard)
   - finalize_refund_with_psbt: btc_pending_infos.insert(same_txid, ...) → is_none() == false
   - PANIC: "pending info already exist"
6. Alice calls request_refund again → PANIC: "UTXO already verified via deposit"
7. Relayer calls verify_deposit → PANIC: "Already deposit utxo"
8. Alice's BTC is permanently locked; recovery requires DAO + relayer intervention
   and a contract upgrade to clear verified_deposit_utxo.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L35-43)
```rust
        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs (L127-134)
```rust
    pub fn get_pending_id(&self) -> String {
        self.psbt
            .clone()
            .extract_tx()
            .expect("ERR_EXTRACT_TX: failed to extract transaction from PSBT")
            .compute_txid()
            .to_string()
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-372)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };

        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L418-424)
```rust
        require!(
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/tests/test_refund.rs (L1484-1572)
```rust
/// A *different* account cannot duplicate or hijack a refund that is already being
/// executed. Two protections apply on Bitcoin:
///   1. a non-privileged account is still gated by the timelock;
///   2. once past the timelock it rebuilds the identical tx (same id), so the
///      insert is rejected — the pending tx stays owned by the original caller.
#[tokio::test]
#[cfg(not(feature = "zcash"))]
async fn test_refund_execute_twice_different_account() {
    let worker = near_workspaces::sandbox().await.unwrap();
    let context = Context::new(&worker, Some(CHAIN.to_string())).await;

    let refund_btc_address = TARGET_ADDRESS;
    let deposit_msg = DepositMsg {
        recipient_id: context.get_account_by_name("alice").sdk_id(),
        post_actions: None,
        extra_msg: None,
        safe_deposit: None,
        refund_address: Some(refund_btc_address.to_string()),
    };
    let deposit_address = context
        .get_user_deposit_address(deposit_msg.clone())
        .await
        .unwrap();
    let tx_bytes = generate_transaction_bytes(
        vec![(
            "a2a5069f02ad4ca31a16113903ab9fe9e8da6ddf20cad4b461b71e8b96050f19",
            0,
            None,
        )],
        vec![(deposit_address.as_str(), 100_000)],
    );
    let vout: u32 = 0;

    check!(context.request_refund(
        "alice",
        deposit_msg.clone(),
        TARGET_ADDRESS,
        tx_bytes.clone(),
        vout,
        "0000000000000c3f818b0b6374c609dd8e548a0a9e61065e942cd466c426e00d".to_string(),
        1,
        vec![],
        None
    ));
    let key = utxo_storage_key(&tx_bytes, vout);

    // Short timelock so we can fast-forward past it deterministically.
    context
        .get_account_by_name("root")
        .call(context.bridge_contract.id(), "update_config")
        .args_json(json!({"update": {"refund_timelock_sec": 200}}))
        .deposit(near_sdk::NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await
        .unwrap()
        .unwrap();

    // root (DAO) fast-tracks the pre-authorized address (timelock 0).
    check!(print "execute_refund #1 (root)" context.execute_refund("root", &key));
    let pending1 = context.get_btc_pending_infos_paged().await.unwrap();
    assert_eq!(pending1.len(), 1);
    let id1 = pending1.keys().next().unwrap().clone();

    // (1) A non-privileged different account (bob) is still gated by the timelock.
    check!(
        context.execute_refund("bob", &key),
        "Refund timelock has not passed yet"
    );

    // (2) After the timelock, bob's call reaches the finalize step but rebuilds the
    // identical tx (same id) and is rejected — no duplicate, no hijack.
    worker.fast_forward(4000).await.unwrap();
    check!(
        context.execute_refund("bob", &key),
        "pending info already exist"
    );

    let pending2 = context.get_btc_pending_infos_paged().await.unwrap();
    assert_eq!(
        pending2.len(),
        1,
        "a different account cannot create a second refund tx"
    );
    assert!(
        pending2.contains_key(&id1),
        "the original refund pending tx is unchanged"
    );
}
```
