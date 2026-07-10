Now I have all the information needed. Let me trace the full path carefully.

### Title
Zcash Refund Re-execution Across NU Activation Boundary Accumulates Multiple `BTCPendingInfo` Entries for the Same Deposit UTXO — (`contracts/satoshi-bridge/src/zcash_utils/refund.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`load_refund_request_for_execute` intentionally permits re-execution of a refund when `executed == true`. On the Zcash path, the `btc_pending_id` is the Zcash V5 txid, which commits to `branch_id` (ZIP-244). Because refunds always use `expiry_height = 0`, the only variable between two calls is `branch_id`. Two different unprivileged callers — one before and one after a NU activation boundary — each produce a distinct `btc_pending_id` for the same deposit UTXO. The per-caller `require_pending_sign_capacity` guard does not prevent a second caller from inserting a second entry. The result is two live `BTCPendingInfo` records in `btc_pending_infos` for the same UTXO, violating the one-active-pending-per-UTXO invariant.

---

### Finding Description

**Entry point — public, payable, no role check:** [1](#0-0) 

**Guard that explicitly allows re-execution when `executed == true`:** [2](#0-1) 

The comment at line 250-252 confirms this is intentional: *"re-running execute_refund is allowed — re-creating the refund tx, e.g. after a consensus branch change."* This is the design rationale, but it opens the accumulation window.

**Zcash `execute_refund_callback` fixes `expiry_height = 0` for all refunds:** [3](#0-2) [4](#0-3) 

**`get_pending_id` computes the Zcash V5 txid, which commits to `branch_id`:** [5](#0-4) [6](#0-5) 

Because `expiry_height = 0` is constant and all other transaction fields (inputs, outputs, amounts) are fixed by the refund request, the only thing that changes the txid between two calls is `branch_id`.

**`branch_id` changes at NU activation boundaries:** [7](#0-6) 

On mainnet: Nu6 → Nu6_1 at block 3,146,400; Nu6_1 → Nu6_2 at block 3,364,600.

**`finalize_refund_with_psbt` only blocks insertion if the same `btc_pending_id` already exists:** [8](#0-7) 

If `pending_id_A != pending_id_B` (guaranteed by different `branch_id`), the second `insert` returns `None` and the `require!` passes.

**`require_pending_sign_capacity` is per-caller, not per-UTXO:** [9](#0-8) 

After Alice's first call, Alice's `btc_pending_sign_ids` has 1 entry and she is blocked (default max = 1). Bob, a fresh account, has 0 entries and passes the check freely.

**Stale entries cannot be cleaned up while the refund request is still active:** [10](#0-9) 

Until one of the two pending entries is finalized via `verify_refund_finalize` (which removes the refund request), the other entry is stuck and cannot be removed.

---

### Impact Explanation

Two distinct `BTCPendingInfo` records exist in `btc_pending_infos` for the same deposit UTXO:

- Both consume bridge MPC signing capacity. The default per-account limit is 1, but since the two entries are owned by different accounts, the global signing queue is inflated.
- The MPC pipeline is asked to sign two different transactions spending the same UTXO. Only one can confirm on-chain; the other is permanently unconfirmable until the refund request is removed.
- The stuck entry cannot be cleaned up via `remove_refund_pending_tx_id` while the refund request is active, requiring operator intervention.
- If the second entry uses a `branch_id` that is no longer valid on the Zcash network (e.g., the first entry used Nu6_1 and the network has moved to Nu6_2), the bridge may attempt to verify a transaction that can never confirm, permanently blocking that signing slot.

This matches the Medium impact category: *stuck bridge state requiring operator intervention* and *non-atomic cross-contract state corruption*.

---

### Likelihood Explanation

- NU activation heights are publicly known and scheduled well in advance (mainnet: blocks 3,146,400 and 3,364,600).
- An attacker needs only two NEAR accounts and the `required_balance_for_execute_refund` deposit for each call.
- The timelock must have passed, but after that the path is fully permissionless.
- The attacker does not need any privileged role, leaked key, or external dependency.

---

### Recommendation

Add a per-UTXO guard in `finalize_refund_with_psbt` that removes the previous pending entry (if any) before inserting the new one, or rejects the second call if any live `BTCPendingInfo` already references the same `utxo_storage_key`. Concretely, the refund request could store the current `btc_pending_id` and `finalize_refund_with_psbt` could remove the old entry before inserting the new one, ensuring at most one active pending entry per UTXO at all times.

---

### Proof of Concept

```
State: refund request for UTXO "txid@0" exists with executed=false.

1. Alice calls execute_refund("txid@0") at Zcash block height 3,100,000 (Nu6 branch_id).
   → execute_refund_callback runs with last_block_height=3,100,000
   → branch_id = Nu6
   → expiry_height = 0
   → pending_id_A = txid(Nu6, expiry=0, vin=[txid@0], vout=[refund_addr])
   → btc_pending_infos[pending_id_A] = BTCPendingInfo{...}
   → refund_request.executed = true

2. Zcash network crosses block 3,146,400 (Nu6_1 activation).

3. Bob calls execute_refund("txid@0") at Zcash block height 3,200,000 (Nu6_1 branch_id).
   → load_refund_request_for_execute: executed==true → passes (line 254-258)
   → execute_refund_callback runs with last_block_height=3,200,000
   → branch_id = Nu6_1
   → expiry_height = 0
   → pending_id_B = txid(Nu6_1, expiry=0, vin=[txid@0], vout=[refund_addr])
   → pending_id_B != pending_id_A (branch_id differs → different ZIP-244 digest)
   → require_pending_sign_capacity(Bob): Bob has 0 pending → passes
   → require!(btc_pending_infos.insert(pending_id_B).is_none()): pending_id_B is new → passes
   → btc_pending_infos[pending_id_B] = BTCPendingInfo{...}

Result: btc_pending_infos contains both pending_id_A and pending_id_B,
        both referencing the same deposit UTXO "txid@0".
        Neither can be removed until the refund request is gone.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L250-258)
```rust
        // Block only if the UTXO was claimed by a deposit. If it was claimed by
        // our own refund (executed == true, which also set verified_deposit_utxo),
        // re-running execute_refund is allowed — re-creating the refund tx, e.g.
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-372)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
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

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L13-13)
```rust
pub(crate) const REFUND_EXPIRY_HEIGHT: u32 = 0;
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L96-96)
```rust
        let expiry_height = REFUND_EXPIRY_HEIGHT;
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L413-415)
```rust
        let inner_tx = TransactionData::from_parts(
            TxVersion::V5,
            self.branch_id,
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L431-433)
```rust
    pub fn get_pending_id(self) -> String {
        self.get_zcash_tx().compute_txid().to_string()
    }
```

**File:** contracts/satoshi-bridge/src/network.rs (L53-65)
```rust
    pub fn get_branch_id(&self, block_height: u32) -> BranchId {
        let block_height_update = BranchIdUpdateBlockHeight::new(self);
        if block_height_update.nu6_2_update != 0 && block_height >= block_height_update.nu6_2_update
        {
            return BranchId::Nu6_2;
        }
        if block_height_update.nu6_1_update != 0 && block_height >= block_height_update.nu6_1_update
        {
            return BranchId::Nu6_1;
        }

        BranchId::Nu6
    }
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
