### Title
Unprivileged Caller Can Redirect Another User's BTC Refund to an Arbitrary Address - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary

`request_refund` verifies the BTC transaction proof and the attached storage deposit, but never checks that the caller is the `deposit_msg.recipient_id` — the NEAR account that is the intended beneficiary of the deposit. When `deposit_msg.refund_address` is `None`, any unprivileged account can submit a refund request for another user's unfinalized deposit and supply an arbitrary attacker-controlled BTC address as the refund destination.

### Finding Description

`request_refund` (public, callable by anyone) delegates to `internal_request_refund`. The function performs the following checks:

1. Attached NEAR deposit covers storage cost.
2. `tx_bytes` length is within bounds.
3. If `deposit_msg.refund_address` is `Some(x)`, the provided `refund_address` must equal `x`.
4. The BTC transaction is included in the chain (Light Client proof).
5. In the callback, the output script matches the deposit address derived from `deposit_msg`. [1](#0-0) 

What is **never** checked: whether `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. The caller's identity is not recorded and not validated against the deposit's intended NEAR recipient. [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the caller freely supplies any `refund_address` string. The callback stores it verbatim: [3](#0-2) 

`execute_refund` is also callable by anyone after the timelock elapses — no ownership check there either: [4](#0-3) 

The `unsafe_refund_timelock_sec` defaults to 14 days, giving DAO/Operator a window to call `reject_refund`. However, this is an operational safeguard, not a protocol-level authorization check, and it can be bypassed if the DAO does not monitor all incoming refund requests. [5](#0-4) 

### Impact Explanation

An attacker who learns a victim's `deposit_msg` (emitted on-chain via `Event::LogDepositAddress` when `get_user_deposit_address` is called, or reconstructable from the BTC transaction and the deposit address derivation) can:

1. Submit `request_refund` with the victim's `deposit_msg` and the attacker's own BTC address as `refund_address`.
2. Wait 14 days (or less if the DAO is inattentive).
3. Call `execute_refund`, causing the bridge's MPC network to sign a Bitcoin transaction sending the victim's BTC to the attacker's address.

The victim's BTC is permanently redirected. This matches the **Medium** impact tier (attacker-triggered stuck/redirected bridge state requiring operator intervention to prevent), with escalation to **Critical** (theft of user BTC) if the DAO fails to reject within the timelock window.

### Likelihood Explanation

- `deposit_msg` is public: `get_user_deposit_address` emits `Event::LogDepositAddress` containing the full `deposit_msg`.
- Unfinalized deposits are a normal operational scenario (relayer downtime, network issues).
- The attacker only needs to pay a small NEAR storage deposit as an anti-spam fee.
- The 14-day timelock is the only mitigation, and it relies entirely on DAO vigilance — there is no on-chain enforcement that the caller owns the deposit.

### Recommendation

Add an authorization check in `internal_request_refund` (or at the `request_refund` entry point) that requires the caller to be the `deposit_msg.recipient_id`:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id
        || self.acl_has_role(Role::DAO.into(), env::predecessor_account_id())
        || self.acl_has_role(Role::Operator.into(), env::predecessor_account_id()),
    "Only the deposit recipient or a privileged role may request a refund"
);
```

This mirrors the fix applied in the KUMA report: add the missing party (the resource owner/beneficiary) to the authorization check, rather than relying solely on an operational timelock to catch abuse.

### Proof of Concept

1. Alice calls `get_user_deposit_address(deposit_msg)` where `deposit_msg = {recipient_id: "alice.near", refund_address: None, ...}`. The event `LogDepositAddress` is emitted on-chain, revealing the full `deposit_msg`.
2. Alice sends BTC to the derived deposit address. The relayer never calls `verify_deposit` (e.g., due to downtime).
3. Attacker Bob observes the on-chain event, reconstructs `deposit_msg`, and calls:
   ```
   request_refund(
       deposit_msg,          // Alice's deposit_msg
       "bob_btc_address",    // Attacker's BTC address
       tx_bytes,             // Alice's BTC transaction bytes (public on Bitcoin)
       vout,
       proof,
       None
   )
   ```
   with sufficient attached NEAR for storage.
4. `request_refund_callback` verifies the BTC proof and stores the refund request with `refund_address = "bob_btc_address"`. No check is made that Bob is Alice.
5. After `unsafe_refund_timelock_sec` (14 days), Bob calls `execute_refund`. The bridge constructs and MPC-signs a Bitcoin transaction paying Alice's BTC to Bob's address.
6. Alice's BTC is permanently stolen. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L496-580)
```rust
    #[private]
    pub fn request_refund_callback(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        gas_fee: Option<u128>,
    ) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

        // Verify that the output script matches the deposit address derived from deposit_msg
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());

        true
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
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

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```
