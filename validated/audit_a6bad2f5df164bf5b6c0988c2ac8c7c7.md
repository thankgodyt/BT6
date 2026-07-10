### Title
Excess NEAR Attached Deposit Permanently Locked in `execute_refund` and `request_refund` — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

Both `execute_refund` and `request_refund` are `#[payable]` functions that enforce a minimum attached NEAR deposit via a `>=` check, but neither function refunds any surplus NEAR to the caller. Any NEAR sent above the required minimum is silently absorbed into the contract's balance with no recovery path, permanently locking user funds.

---

### Finding Description

`execute_refund` delegates its deposit check to `resolve_execute_refund_timelock`:

```rust
// contracts/satoshi-bridge/src/refund.rs, lines 202–205
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
```

The check is a `>=` comparison, so any amount above the minimum is accepted. After the check, the function proceeds to build the refund PSBT and update state — but never issues a `Promise::transfer` back to `env::predecessor_account_id()` for the surplus. The full `attached_deposit` is absorbed into the contract's NEAR balance.

The same pattern exists in `internal_request_refund`:

```rust
// contracts/satoshi-bridge/src/refund.rs, lines 146–149
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
```

The public-facing `request_refund` entry point in `bridge.rs` (lines 508–535) carries a doc comment stating "The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee," but this only documents that the *minimum* is intentionally kept; it does not justify silently consuming any arbitrary excess the caller attaches. No code path in either function computes `attached_deposit - required_minimum` and returns it to the caller. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

Any NEAR attached above the required minimum is permanently locked inside the bridge contract. There is no `lost_found` map for NEAR (only for nBTC), no admin withdrawal path for arbitrary NEAR balances, and no way for the caller to reclaim the overpayment. This constitutes a permanent, irreversible loss of user funds (NEAR tokens) triggered by a normal, unprivileged call to a public bridge function.

Allowed impact matched: **Medium — harmful smart-contract behavior without direct funds theft; stuck/lost user funds requiring no operator intervention to trigger but with no recovery path.** [5](#0-4) 

---

### Likelihood Explanation

Both `execute_refund` and `request_refund` are callable by any unprivileged NEAR account. Users routinely attach a small buffer above the minimum to avoid "Insufficient deposit" reverts — a standard practice on NEAR. Wallets and dApps that do not compute the exact required balance will silently over-attach. The trigger requires no special knowledge or coordination; it is a normal usage pattern. [6](#0-5) 

---

### Recommendation

After the minimum required deposit is consumed, compute the surplus and return it to the caller:

```rust
let required = self.required_balance_for_execute_refund();
let attached = env::attached_deposit();
require!(attached >= required, "Insufficient deposit for storage");
let surplus = attached.saturating_sub(required);
if surplus > NearToken::from_yoctonear(0) {
    Promise::new(env::predecessor_account_id()).transfer(surplus);
}
```

Apply the same pattern in `internal_request_refund`. If the full deposit is intentionally non-refundable for `request_refund` (anti-spam), document and enforce an exact-amount check (`== required`) rather than `>=` to prevent accidental over-payment. [7](#0-6) [8](#0-7) 

---

### Proof of Concept

1. A refund request exists for UTXO key `"abc123@0"` and its timelock has elapsed.
2. The bridge's `required_balance_for_execute_refund()` returns `100_000_000_000_000_000_000_000` yoctoNEAR (0.1 NEAR).
3. A user calls `execute_refund("abc123@0", None)` attaching `500_000_000_000_000_000_000_000` yoctoNEAR (0.5 NEAR) — a common practice to ensure the call does not revert.
4. `resolve_execute_refund_timelock` passes the `>=` check and the function completes successfully.
5. The contract's NEAR balance increases by 0.5 NEAR; the caller receives nothing back.
6. The 0.4 NEAR surplus has no recovery path: it is not tracked in `lost_found`, not accessible via `withdraw_protocol_fee` (which operates on nBTC protocol fees, not raw NEAR), and not returnable by any other public function. [9](#0-8) [10](#0-9)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-184)
```rust
    pub(crate) fn internal_request_refund(
        &self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<u128>,
    ) -> Promise {
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }

        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L198-228)
```rust
    /// Validate the attached storage deposit and resolve the timelock that must
    /// elapse before this refund can be executed. Shared by the Bitcoin and
    /// Zcash `execute_refund` entrypoints.
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-535)
```rust
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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-75)
```rust
    pub fn transfer_nbtc_callback(&mut self, account_id: AccountId, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::TransferNbtc {
            account_id: &account_id,
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
                amount,
            }
            .emit();
        }
        event.emit();
        promise_success
    }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L19-29)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn withdraw_protocol_fee(&mut self, amount: Option<U128>) -> Promise {
        assert_one_yocto();
        let total_protocol_fee = self.data().cur_available_protocol_fee;
        let amount = amount.map_or(total_protocol_fee, |v| v.0);
        require!(amount > 0 && amount <= total_protocol_fee, "Invalid amount");
        self.data_mut().cur_available_protocol_fee -= amount;
        self.data_mut().acc_claimed_protocol_fee += amount;
        self.internal_withdraw_protocol_fee(amount)
    }
```
