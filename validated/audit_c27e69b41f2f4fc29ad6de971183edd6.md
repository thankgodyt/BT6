### Title
DAO `cancel_withdraw` Permanently Blocked by User Filling `btc_pending_sign_ids` to Capacity — (`contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs`)

---

### Summary

`cancel_withdraw` checks the **user's** pending-sign capacity before creating the cancel-RBF entry. A user can fill their own `btc_pending_sign_ids` to the per-account limit (default: 1) via a concurrent refund execution or second withdrawal, causing `require_pending_sign_capacity` to panic and permanently blocking the DAO/Operator from canceling the stuck withdrawal.

---

### Finding Description

`cancel_withdraw` in `api/bridge.rs` is gated by `require_pending_sign_capacity(&user_account_id)`: [1](#0-0) 

`require_pending_sign_capacity` panics if `pending_sign_count() >= get_max_pending_sign_txs(account_id)`. The default limit returned for any account not in `pending_tx_limits` is **1**: [2](#0-1) 

When the original withdrawal is fully signed, `sign_btc_transaction_callback` removes its ID from `btc_pending_sign_ids` and moves it to `btc_pending_verify_list`: [3](#0-2) 

This is confirmed by the test asserting `btc_pending_sign_ids` is empty once the tx reaches PendingVerify: [4](#0-3) 

So when `cancel_withdraw` is called (which requires the original tx to be in PendingVerify), the user's `btc_pending_sign_ids` is empty. The user can then fill it to the limit of 1 by executing a refund. `finalize_refund_with_psbt` inserts a new pending-sign ID into the user's `btc_pending_sign_ids`: [5](#0-4) 

With `btc_pending_sign_ids.len() == 1` (at the default limit), the DAO's subsequent `cancel_withdraw` call hits `require_pending_sign_capacity`, which evaluates `1 < 1` → false → panics with `"Too many pending sign transactions"`.

The `define_rbf_method!` macro confirms the capacity check in `cancel_withdraw` (line 291 of `api/bridge.rs`) runs **before** the new cancel-RBF pending ID is inserted into `btc_pending_sign_ids`: [6](#0-5) 

---

### Impact Explanation

The DAO/Operator cannot cancel a stuck withdrawal. The original UTXO remains locked in the bridge indefinitely. The user's nBTC tokens are already burned/held. This is a stuck-state with no automatic recovery path — the DAO would need to first raise the user's `pending_tx_limits` as a workaround, which is an out-of-band privileged action not part of the normal cancel flow.

---

### Likelihood Explanation

The precondition is realistic: any user with a withdrawal stuck in PendingVerify who also has a separate deposit UTXO eligible for refund can execute this. The refund path (`execute_refund` → `finalize_refund_with_psbt`) is publicly callable. The user only needs to call it before the DAO calls `cancel_withdraw` after `max_btc_tx_pending_sec` elapses. The default limit of 1 makes this trivially achievable with a single refund execution.

---

### Recommendation

Remove `require_pending_sign_capacity(&user_account_id)` from `cancel_withdraw` (and analogously from `cancel_active_utxo_management`). The capacity guard exists to prevent users from flooding the signing queue with their own transactions; it must not gate privileged protocol-recovery operations. The cancel-RBF entry can be inserted unconditionally, or a separate higher limit can be reserved for cancel operations. [1](#0-0) [7](#0-6) 

---

### Proof of Concept

```
1. Alice initiates a withdrawal → original tx enters PendingSign,
   alice.btc_pending_sign_ids = {orig_id}

2. Relayer signs all inputs → tx moves to PendingVerify,
   alice.btc_pending_sign_ids = {}   (removed in sign_btc_transaction_callback)

3. Alice calls execute_refund (for a separate deposit UTXO she controls)
   → finalize_refund_with_psbt inserts refund_pending_id
   alice.btc_pending_sign_ids = {refund_id}   (count = 1 = limit)

4. max_btc_tx_pending_sec elapses.

5. DAO calls cancel_withdraw(orig_id):
   → require_pending_sign_capacity(&alice):
      alice.pending_sign_count() = 1
      get_max_pending_sign_txs(&alice) = 1
      require!(1 < 1)  →  PANIC: "Too many pending sign transactions"

Result: cancel_withdraw is permanently blocked; original UTXO locked.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L285-299)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L411-428)
```rust
    pub fn cancel_active_utxo_management(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
    ) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
        self.cancel_active_utxo_management_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L105-123)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L197-207)
```rust
                let is_original_tx = btc_pending_info.get_original_tx_id().is_none();
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
                if is_original_tx {
                    account
                        .btc_pending_verify_list
                        .insert(btc_pending_sign_id.clone());
                }
```

**File:** contracts/satoshi-bridge/tests/test_satoshi_bridge.rs (L412-418)
```rust
    assert!(context
        .get_account("alice")
        .await
        .unwrap()
        .unwrap()
        .btc_pending_sign_ids
        .is_empty());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L342-375)
```rust
        self.require_pending_sign_capacity(&caller);

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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L9-43)
```rust
macro_rules! define_rbf_method {
    ($method:ident, $internal_fn:ident) => {
        pub(crate) fn $method(
            &mut self,
            account_id: AccountId,
            original_btc_pending_verify_id: String,
            output: Vec<TxOut>,
            _chain_specific_data: Option<ChainSpecificData>,
        ) {
            let predecessor_account_id = env::predecessor_account_id();
            let original_tx_btc_pending_info =
                self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);

            let new_psbt = self.generate_psbt_from_original_psbt_and_new_output(
                original_tx_btc_pending_info,
                output,
            );

            let btc_pending_id = self.$internal_fn(
                &account_id,
                original_btc_pending_verify_id,
                new_psbt,
                predecessor_account_id,
            );

            self.internal_unwrap_mut_account(&account_id)
                .btc_pending_sign_ids
                .insert(btc_pending_id.clone());

            Event::GenerateBtcPendingInfo {
                account_id: &account_id,
                btc_pending_id: &btc_pending_id,
            }
            .emit();
        }
```
