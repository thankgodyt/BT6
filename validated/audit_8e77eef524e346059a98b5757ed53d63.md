### Title
`finalize_refund_with_psbt` Does Not Check If UTXO Was Already Deposited, Enabling Double-Claim of nBTC and BTC — (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`execute_refund` (via `finalize_refund_with_psbt`) inserts the UTXO into `verified_deposit_utxo` to block *future* `verify_deposit` calls, but never checks whether `verify_deposit` has *already* succeeded for that UTXO. A user who calls `request_refund` before the relayer calls `verify_deposit` can later call `execute_refund` after the deposit is finalized, receiving both minted nBTC and their BTC back via the refund path.

---

### Finding Description

The bridge has two competing finalization paths for the same on-chain UTXO:

**Deposit path:** `verify_deposit` → light-client proof → `verify_deposit_callback` → `mint` nBTC → adds UTXO to `verified_deposit_utxo`.

**Refund path:** `request_refund` → light-client proof → stores `RefundRequest` → (timelock) → `execute_refund` → `finalize_refund_with_psbt` → creates `BTCPendingInfo{state: Refund}` → adds UTXO to `verified_deposit_utxo` → MPC signs → `verify_refund_finalize` → BTC returned.

The cross-path guard is `verified_deposit_utxo`. `request_refund` correctly checks it and rejects if the UTXO was already deposited. `verify_deposit` correctly checks it and rejects if the UTXO was already refunded. **However, `finalize_refund_with_psbt` only inserts into `verified_deposit_utxo`; it never reads it first:**

```rust
// Mark UTXO as verified to prevent verify_deposit later
self.data_mut()
    .verified_deposit_utxo
    .insert(utxo_storage_key.clone());
``` [1](#0-0) 

The comment itself reveals the design intent: this is a *forward* guard only. There is no `require!(!self.data().verified_deposit_utxo.contains(...))` before this line.

**Attack sequence:**

1. Attacker sends BTC to a deposit address that encodes their NEAR account and a `refund_address`.
2. Attacker immediately calls `request_refund` — the UTXO is not yet in `verified_deposit_utxo`, so it succeeds and stores a `RefundRequest`.
3. The relayer (normal operation) calls `verify_deposit` — the UTXO is not yet in `verified_deposit_utxo` (only the `RefundRequest` exists, which `verify_deposit` does not check), so it succeeds, mints nBTC to the attacker, and adds the UTXO to `verified_deposit_utxo`.
4. Attacker waits for `refund_timelock_sec` to expire, then calls `execute_refund`.
5. `execute_refund` calls `finalize_refund_with_psbt`, which creates a `BTCPendingInfo` with `state: PendingInfoState::Refund(...)` and re-inserts the UTXO into `verified_deposit_utxo` (a no-op on the set, no panic, no check). [2](#0-1) 

6. MPC signs the refund transaction; `verify_refund_finalize` confirms it on-chain and returns BTC to the attacker's `refund_address`.
7. Attacker now holds both the minted nBTC **and** the original BTC — a complete double-claim.

The `verify_deposit` path does not check `refund_requests` before minting: [3](#0-2) 

And `create_btc_pending_info` / `finalize_refund_with_psbt` both proceed without cross-checking the other path's state: [4](#0-3) 

---

### Impact Explanation

**Critical.** The attacker receives nBTC (backed by BTC that was supposed to remain locked) while simultaneously recovering the underlying BTC via the refund path. This is unauthorized minting: nBTC is issued without a permanently locked BTC backing, directly inflating the circulating supply beyond the backed amount and draining bridge-controlled BTC funds.

---

### Likelihood Explanation

**Medium-High.** The only prerequisite is that the attacker calls `request_refund` before the relayer calls `verify_deposit` for the same UTXO. Because the attacker controls the timing of their own `request_refund` call and can submit it in the same block as (or immediately after) the BTC transaction confirms, this race is reliably winnable. No privileged access, leaked keys, or external dependency compromise is required — only a standard unprivileged NEAR account.

---

### Recommendation

In `finalize_refund_with_psbt`, add an explicit guard before inserting into `verified_deposit_utxo`:

```rust
require!(
    !self.data().verified_deposit_utxo.contains(&utxo_storage_key),
    "UTXO already finalized via deposit"
);
self.data_mut()
    .verified_deposit_utxo
    .insert(utxo_storage_key.clone());
``` [1](#0-0) 

Symmetrically, `verify_deposit_callback` should check whether a `RefundRequest` already exists for the UTXO and reject if so, closing the race in both directions.

---

### Proof of Concept

```
1. Alice sends 100,000 sat to her deposit address (encodes alice.near + refund_address=bc1qalice).
2. Alice calls request_refund(deposit_msg, tx_proof, ...).
   → RefundRequest stored; verified_deposit_utxo does NOT contain the key yet. ✓
3. Relayer calls verify_deposit(deposit_msg, tx_proof, ...).
   → verify_deposit does not check refund_requests.
   → Light client confirms inclusion.
   → verify_deposit_callback mints ~100,000 sat worth of nBTC to alice.near.
   → UTXO added to verified_deposit_utxo.
4. Alice waits for refund_timelock_sec to expire.
5. Alice calls execute_refund(utxo_storage_key).
   → finalize_refund_with_psbt is called.
   → No require!(!verified_deposit_utxo.contains(...)) check.
   → BTCPendingInfo{state: Refund} created successfully.
   → verified_deposit_utxo.insert(...) is a no-op (already present), no panic.
6. Alice calls sign_btc_transaction → MPC signs the refund PSBT.
7. Relayer calls verify_refund_finalize → BTC returned to bc1qalice.
Result: Alice holds nBTC (≈100,000 sat) AND recovered her 100,000 sat BTC.
``` [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L315-402)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

        let deposit_msg = refund_request.deposit_msg();
        let path = get_deposit_path(&deposit_msg);
        let vutxo = VUTXO::Current(UTXO {
            path,
            tx_bytes: refund_request.tx_bytes.0.clone(),
            vout: refund_request.vout,
            balance: u64::try_from(refund_request.amount)
                .unwrap_or_else(|_| env::panic_str("Amount overflow")),
        });

        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
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

        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L37-65)
```rust
    pub(crate) fn internal_verify_withdraw_entry(
        &mut self,
        tx_id: String,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
        coinbase_proof: Option<(String, Vec<String>)>,
    ) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        btc_pending_info.assert_withdraw_related_pending_verify_tx();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            require!(
                self.check_btc_pending_info_exists(original_tx_id),
                "original tx already verified"
            );
        }
        require!(
            btc_pending_info.tx_bytes_with_sign.is_some(),
            "Missing tx_bytes_with_sign"
        );
        self.internal_verify_withdraw(
            tx_id,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            coinbase_proof,
            btc_pending_info,
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L71-85)
```rust
    pub(crate) fn create_btc_pending_info(
        &mut self,
        sender_id: AccountId,
        amount: u128,
        target_btc_address: String,
        mut psbt: PsbtWrapper,
        max_gas_fee: Option<U128>,
    ) {
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );
```
