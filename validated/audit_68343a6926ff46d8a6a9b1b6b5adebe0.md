### Title
Attacker Can Front-Run `request_refund` with Attacker-Controlled `refund_address` to Grief Depositors and Redirect BTC Refunds - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
When a user deposits BTC with `deposit_msg.refund_address = None`, any NEAR account can call `request_refund` using the user's public `deposit_msg` while supplying an attacker-controlled BTC `refund_address`. The stored refund request is keyed by UTXO, so the duplicate-request guard permanently blocks the legitimate user from registering their own request. After `unsafe_refund_timelock_sec` (14 days by default), the attacker calls the permissionless `execute_refund`, causing the bridge's MPC to sign a transaction that sends the deposited BTC to the attacker's address.

### Finding Description

`request_refund` is a public, payable function (no individual `#[trusted_relayer]` guard) in the `#[trusted_relayer]` impl block at line 480 of `api/bridge.rs`. The only caller-identity check is:

```rust
// refund.rs:154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

When `deposit_msg.refund_address` is `None`, the branch is skipped entirely and any caller-supplied `refund_address` is accepted verbatim. The callback then stores the request:

```rust
// refund.rs:564-578
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-supplied address
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
```

A subsequent legitimate `request_refund` for the same UTXO is rejected by the duplicate guard:

```rust
// refund.rs:544-547
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

`execute_refund` is explicitly documented as callable by anyone after the timelock:

```
// api/bridge.rs:487
/// After the timelock period, anyone can call `execute_refund` to initiate the return.
```

`resolve_execute_refund_timelock` applies `unsafe_refund_timelock_sec` (14 days) when `deposit_msg.refund_address` is `None`, giving DAO/Operator a window to reject. However, this is a manual, off-chain process with no on-chain guarantee. If the operator does not act, `execute_refund` proceeds and `finalize_refund_with_psbt` builds a PSBT paying the attacker's address:

```rust
// refund.rs:324
let refund_address = refund_request.refund_address.clone();
// ...
// refund.rs:382-386
Event::RefundExecuted {
    utxo_storage_key: utxo_storage_key.clone(),
    amount: refund_request.amount.into(),
    refund_address,   // ← attacker's address emitted and used in PSBT output
}
```

The MPC then signs the transaction, and the attacker broadcasts it to claim the BTC.

### Impact Explanation

- **Immediate (Medium):** The legitimate depositor's UTXO is locked for at least 14 days. They cannot register their own refund request. They must rely on DAO/Operator to reject the malicious request before they can proceed.
- **Escalated (Critical):** If DAO/Operator fails to reject within `unsafe_refund_timelock_sec`, the attacker executes the refund and permanently redirects the deposited BTC to their own address — a direct theft of user funds with no on-chain recovery path.

### Likelihood Explanation

- `deposit_msg` is public: it is logged on-chain via `get_user_deposit_address` events and is derivable from the Bitcoin transaction itself.
- The BTC transaction and Merkle proof are publicly available on the Bitcoin blockchain.
- The attacker only needs to pay the anti-spam NEAR deposit (`required_balance_for_request_refund()`), a small cost relative to the BTC value at risk.
- The 14-day window requires continuous DAO/Operator vigilance; a single missed alert is sufficient for the attacker to succeed.

### Recommendation

1. **Bind `refund_address` to the caller when `deposit_msg.refund_address` is `None`:** Store `env::predecessor_account_id()` alongside the request and require the same account to call `execute_refund`, or require the caller to prove ownership of the BTC address (e.g., via a signed message).
2. **Alternatively, require `deposit_msg.refund_address` to always be `Some`:** Eliminate the `None` path entirely, forcing users to pre-authorize a refund address at deposit time.
3. **Or restrict `request_refund` to the `deposit_msg.recipient_id`:** Only the NEAR account named in the deposit message should be allowed to register a refund request when no refund address was pre-authorized.

### Proof of Concept

1. Alice deposits BTC, generating `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The deposit address and `deposit_msg` are logged on-chain.
2. `verify_deposit` is never called (relayer is down).
3. Attacker observes the BTC transaction on-chain and the logged `deposit_msg`.
4. Attacker calls `request_refund(deposit_msg, "attacker_btc_address", tx_bytes, vout, proof, None)` with sufficient NEAR deposit.
5. `internal_request_refund` → light-client verification passes → `request_refund_callback` stores `RefundRequest { refund_address: "attacker_btc_address", ... }`.
6. Alice calls `request_refund` with her own BTC address → rejected: `"Refund request already exists for this UTXO"`.
7. 14 days pass; DAO/Operator does not notice or act.
8. Attacker calls `execute_refund(utxo_storage_key)` → `finalize_refund_with_psbt` builds PSBT paying `"attacker_btc_address"` → MPC signs → attacker broadcasts → Alice's BTC is stolen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-158)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L315-401)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-535)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    // ── Refund API ──

    /// Submit a refund request for a deposit that was never finalized via `verify_deposit` or `safe_verify_deposit`.
    /// The BTC transaction is verified through the Light Client to prove the deposit exists.
    /// After the timelock period, anyone can call `execute_refund` to initiate the return.
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
    /// # Arguments
    ///
    /// * `deposit_msg` - The original deposit message. If `deposit_msg.refund_address` is set,
    ///   it must match the provided `refund_address`.
    /// * `refund_address` - BTC address to send the refund to. If `deposit_msg.refund_address`
    ///   is `None`, this value is used directly.
    /// * `tx_bytes` - BTC transaction bytes proving the deposit.
    /// * `vout` - Output index of the deposit in the transaction.
    /// * `proof` - Transaction inclusion proof for Light Client verification, bundling:
    ///   `tx_block_blockhash` (block hash containing the transaction), `tx_index`
    ///   (transaction index within the block), `merkle_proof` (Merkle proof of the
    ///   transaction), and the coinbase fields `coinbase_tx_id` and
    ///   `coinbase_merkle_proof` used to verify the block's coinbase.
    /// * `gas_fee` - Optional custom gas fee. Only DAO or Operator can set this.
    ///   If `None`, the default `config.max_btc_gas_fee` is used during `execute_refund`.
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
