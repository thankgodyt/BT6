### Title
Permissionless `execute_refund` Allows Front-Running to Block Victim Re-Execution and Lock Refund State — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`execute_refund` carries no access control and is callable by any NEAR account for any pending refund request. On Bitcoin, the refund PSBT is fully deterministic (fixed input UTXO, fixed output amount and address, fixed fee), so `get_pending_id()` — the unsigned txid — is identical for any two calls on the same UTXO. An attacker who front-runs a user's `execute_refund` call causes the victim's subsequent call to panic with `"pending info already exist"`, permanently blocking re-execution and leaving the victim's BTC locked in the bridge under the attacker's `BTCPendingInfo` until the attacker cooperates or an operator intervenes.

---

### Finding Description

**1. No access control on `execute_refund`**

`execute_refund` is decorated only with `#[payable]` and `#[pause]`. There is no `#[access_control_any]` or `#[trusted_relayer]` guard. Any NEAR account can call it for any `utxo_storage_key` once the timelock has elapsed. [1](#0-0) 

**2. Bitcoin PSBT is fully deterministic**

The Bitcoin-specific `internal_execute_refund` builds the PSBT synchronously from the fixed deposit `outpoint` and the fixed `refund_output` (amount and address are stored in the `RefundRequest`). No nonce, timestamp, or block-height is mixed in. [2](#0-1) 

**3. `get_pending_id()` returns the unsigned txid — deterministic for Bitcoin**

`get_pending_id()` calls `extract_tx().compute_txid()` on the unsigned transaction. Because inputs and outputs are identical across calls, the txid — and therefore `btc_pending_id` — is the same for any two `execute_refund` calls on the same UTXO. [3](#0-2) 

**4. `finalize_refund_with_psbt` panics on duplicate `btc_pending_id`**

After the attacker's call succeeds and inserts `btc_pending_id = X`, the victim's call reaches the same insertion point and panics with `"pending info already exist"`. [4](#0-3) 

**5. Design intent contradicts implementation**

The code comment explicitly states `execute_refund` is meant to be callable again (e.g., after a consensus branch change), but the deterministic `btc_pending_id` makes re-execution impossible once a `BTCPendingInfo` exists for that UTXO. [5](#0-4) 

**6. The `BTCPendingInfo` is owned by the attacker's account**

`caller` in `finalize_refund_with_psbt` is `env::predecessor_account_id()` — the attacker. The `BTCPendingInfo` is inserted under the attacker's account, and `btc_pending_sign_ids` is updated on the attacker's account. The victim has no handle on this pending info. [6](#0-5) 

**7. Cleanup requires privileged intervention**

`remove_refund_pending_tx_id` is gated behind `#[trusted_relayer]` and additionally requires the refund request to already be gone. The victim cannot unilaterally clean up the stuck state. [7](#0-6) 

---

### Impact Explanation

After the attacker front-runs `execute_refund`:

- The victim's call panics; the victim cannot re-execute the refund (the deterministic `btc_pending_id` is already occupied).
- The refund PSBT is owned by the attacker's account. The attacker must call `sign_btc_transaction` to advance it; if they do not, the BTC remains locked in the bridge indefinitely.
- The victim has no path to recover their BTC without either the attacker's cooperation or a trusted-relayer/operator calling `remove_refund_pending_tx_id` after the request is cleared — both require external intervention.
- Funds are not stolen (the refund output still targets the correct `refund_address`), but they are **attacker-triggered temporarily locked**, matching the Medium impact class: *attacker-triggered temporary locking of bridged funds*.

---

### Likelihood Explanation

- The attack requires no special role, no leaked key, and no privileged access.
- Any NEAR account can call `execute_refund` after paying the storage deposit (`required_balance_for_execute_refund`), which is a small NEAR amount.
- NEAR transactions are visible in the mempool before finalization, making front-running straightforward.
- The attacker only needs to ensure their account has fewer than `get_max_pending_sign_txs` (default: 1) pending sign transactions at the time of the call. [8](#0-7) 

---

### Recommendation

1. **Restrict `execute_refund` to the refund request owner or privileged roles.** Store the requester's NEAR account ID in `RefundRequest` during `request_refund_callback` and enforce `predecessor == refund_request.requester || is_privileged` at the start of `execute_refund`.

2. **Alternatively, allow re-execution by removing the stale `BTCPendingInfo` before inserting a new one.** If `refund_request.executed == true`, look up and remove the old pending info before calling `finalize_refund_with_psbt`, so the design intent (re-creatable refund tx) is actually achievable.

3. **For Bitcoin, mix a non-deterministic element into the PSBT** (e.g., a per-request nonce stored in `RefundRequest`) so that two calls produce different txids and the second call does not collide with the first.

---

### Proof of Concept

```
1. Alice calls request_refund(deposit_msg, "bc1qAlice...", tx_bytes, vout, proof)
   → RefundRequest saved with utxo_storage_key = "abc123@0"

2. Timelock (refund_timelock_sec) elapses.

3. Alice submits execute_refund("abc123@0") — NEAR transaction is pending.

4. Bob observes Alice's pending transaction and submits execute_refund("abc123@0")
   with a higher gas price, front-running Alice.

5. Bob's call executes first:
   - internal_execute_refund builds PSBT: input=abc123:0, output=bc1qAlice..., fee=gas_fee
   - btc_pending_id = txid(unsigned_tx) = "deadbeef..."  ← deterministic
   - finalize_refund_with_psbt(caller=Bob, ...):
       btc_pending_infos.insert("deadbeef...", BTCPendingInfo{account_id: Bob, ...}) → OK
       verified_deposit_utxo.insert("abc123@0")
       refund_request.executed = true

6. Alice's call executes next:
   - load_refund_request_for_execute: executed==true → check passes
   - internal_execute_refund builds identical PSBT → btc_pending_id = "deadbeef..."
   - finalize_refund_with_psbt(caller=Alice, ...):
       btc_pending_infos.insert("deadbeef...", ...) → PANIC: "pending info already exist"

7. Alice's transaction reverts. Alice cannot re-execute execute_refund.

8. Bob's BTCPendingInfo sits in PendingSign state. If Bob does not call
   sign_btc_transaction, Alice's BTC remains locked in the bridge.
   Alice has no permissionless path to recover her funds.
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L622-626)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn remove_refund_pending_tx_id(&mut self, tx_id: String) {
        self.internal_remove_refund_pending_tx_id(tx_id);
    }
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L18-44)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        _chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
    }
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

**File:** contracts/satoshi-bridge/src/refund.rs (L344-375)
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
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L395-401)
```rust
        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
```rust
    pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
        require!(
            self.get_account(account_id)
                .unwrap_or_else(|| {
                    env::panic_str(&format!("ERR_ACCOUNT_NOT_REGISTERED: {}", account_id))
                })
                .pending_sign_count()
                < self.get_max_pending_sign_txs(account_id),
            "Too many pending sign transactions"
        );
    }
```
