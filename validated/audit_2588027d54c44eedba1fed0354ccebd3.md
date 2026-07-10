### Title
Unvalidated `refund_address` Stored in `request_refund` Causes Panic in `execute_refund`, Permanently Blocking the Refund Path for Any Deposit UTXO — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

`internal_request_refund` accepts and stores a caller-supplied `refund_address` string without validating that it is parseable as a valid chain address or that it can produce a `script_pubkey`. Later, `execute_refund` calls `build_refund_output`, which panics via `.expect()` on an invalid or shielded-only address. Because the contract enforces a one-request-per-UTXO invariant and any caller (not just the deposit owner) can submit a refund request, an attacker can front-run a legitimate refund request with a malformed address, permanently blocking the refund path for that UTXO until a DAO operator manually rejects the stuck request.

### Finding Description

**Root cause — no address validation at submission time.**

`internal_request_refund` in `refund.rs` performs only two checks on `refund_address`:

1. If `deposit_msg.refund_address` is `Some`, it asserts the caller-supplied value matches it (line 154–158).
2. It never parses the address or verifies it can produce a `script_pubkey`. [1](#0-0) 

The address is then forwarded verbatim into `request_refund_callback`, which also performs no address-format validation, and is stored in `RefundRequest.refund_address`. [2](#0-1) 

**Panic site — `build_refund_output`.**

When `execute_refund` is later called, it invokes `build_refund_output`, which calls `Address::parse(...).expect(...)` and then `.script_pubkey().expect(...)` on the stored address: [3](#0-2) 

For Bitcoin, any non-address string (e.g., `"INVALID"`) causes `Address::parse` to return `Err`, and `.expect("Invalid refund address")` panics. For Zcash, a shielded-only Unified Address (no transparent receiver) parses successfully but `script_pubkey()` returns `Err`, and `.expect("Invalid refund script_pubkey")` panics. The developers already identified this exact panic class for the Zcash withdrawal path and fixed it in `config.rs`'s `target_script_pubkey`, but `build_refund_output` was not updated. [4](#0-3) 

**No ownership check on `request_refund`.**

`internal_request_refund` does not verify that `env::predecessor_account_id()` matches `deposit_msg.recipient_id`. Any NEAR account can submit a refund request for any deposit UTXO they observe on-chain. [5](#0-4) 

**One-request-per-UTXO invariant blocks the legitimate user.**

`request_refund_callback` enforces that only one refund request can exist per UTXO storage key: [6](#0-5) 

Once an attacker's request with an invalid address is stored, no further refund request can be submitted for that UTXO.

**Attack chain:**

1. Attacker monitors the chain for a new deposit transaction targeting the bridge.
2. Attacker calls `request_refund(deposit_msg, refund_address="INVALID", tx_bytes, vout, proof, ...)` before the legitimate user.
3. `request_refund_callback` stores `RefundRequest { refund_address: "INVALID", ... }`.
4. Legitimate user calls `execute_refund(utxo_storage_key)` → `build_refund_output("INVALID")` → `Address::parse` returns `Err` → `.expect()` panics → transaction reverts, state unchanged.
5. The refund request remains stuck in storage. `execute_refund` will always panic for this request.
6. The legitimate user cannot submit a new refund request (duplicate check fails).
7. The UTXO's refund path is blocked until a DAO/RefundOperator calls `reject_refund`. [7](#0-6) 

### Impact Explanation

The refund path for the targeted UTXO is permanently blocked until privileged operator intervention (`reject_refund`). The deposit path (`verify_deposit`) remains available because `verified_deposit_utxo` is only populated by `finalize_refund_with_psbt`, which is never reached when `execute_refund` panics. However, if the deposit path is also unavailable (e.g., the deposit proof window has expired or the light client is stale), the user's funds are temporarily locked with no self-service recovery. This matches **Medium — attacker-triggered temporary locking of bridged funds requiring operator intervention**.

### Likelihood Explanation

The attack requires no privileged access. The attacker only needs:
- A valid `TxInclusionProof` for the deposit transaction (publicly available on-chain).
- The `deposit_msg` (derivable from the deposit address or observable from prior `get_user_deposit_address` calls).
- A small NEAR storage deposit.

Front-running is straightforward since NEAR transaction ordering is observable. The attacker pays only the storage deposit required by `required_balance_for_request_refund`.

### Recommendation

Validate `refund_address` at submission time in `internal_request_refund`, before the light-client cross-contract call, so an invalid address is rejected immediately:

```rust
// In internal_request_refund, after the refund_address match check:
let parsed = crate::network::Address::parse(&refund_address, config.chain.clone())
    .expect("Invalid refund_address: cannot parse");
parsed.script_pubkey()
    .expect("Invalid refund_address: no transparent receiver");
```

Additionally, add an ownership check so only the deposit recipient (or a privileged role) can submit a refund request for a given UTXO:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id
        || self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()],
                                  env::predecessor_account_id()),
    "Only the deposit recipient may request a refund"
);
```

### Proof of Concept

1. Alice deposits BTC and generates a deposit address via `get_user_deposit_address(deposit_msg)`.
2. The deposit transaction is confirmed on-chain. Attacker observes `tx_bytes`, `vout`, and `deposit_msg`.
3. Attacker calls:
   ```
   request_refund(
     deposit_msg = <Alice's deposit_msg>,
     refund_address = "INVALID_ADDRESS",
     tx_bytes = <valid deposit tx bytes>,
     vout = 0,
     proof = <valid TxInclusionProof>,
     gas_fee = None
   )
   ```
4. `internal_request_refund` decodes the transaction, verifies the proof via the light client, and calls `request_refund_callback`.
5. `request_refund_callback` validates the deposit script matches, stores `RefundRequest { refund_address: "INVALID_ADDRESS", ... }`.
6. Alice calls `execute_refund(utxo_storage_key)`. The contract calls `build_refund_output("INVALID_ADDRESS")`, which calls `Address::parse("INVALID_ADDRESS", chain).expect(...)` → **panic**. Transaction reverts.
7. Alice calls `request_refund(...)` with her own valid address → **panics** with `"Refund request already exists for this UTXO"`.
8. Alice's refund path is permanently blocked. Only a DAO/RefundOperator calling `reject_refund(utxo_storage_key)` can unblock it. [3](#0-2) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L136-184)
```rust
    #[allow(clippy::too_many_arguments)]
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

**File:** contracts/satoshi-bridge/src/refund.rs (L186-196)
```rust
    /// Reject a pending refund request.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L497-513)
```rust
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L426-451)
```rust
    #[test]
    #[cfg(feature = "zcash")]
    fn test_target_script_pubkey_shielded_only_ua_is_none() {
        use crate::network::{Address, Chain};

        let mut unit_env = init_unit_env();
        let config = unit_env.contract.internal_mut_config();
        config.chain = Chain::ZcashMainnet;

        // Real mainnet recipient from the failed withdrawal: Sapling + Orchard, no
        // transparent receiver.
        let shielded_only_ua = "u15a97e324mckwx89t0ucxytpd7v3pfzey7daldrk4mwu3u55ej39f6v7myqjxw0e098hnhyp0tvfgfnxj8swt22rl4f77a8wrg9zjynh9dwj20lf232h7yzfr0v53l2s824l22l63xwlxyypnxkx9qq7dd249pj565q7490fey5czu2pm";

        // Precondition documenting the bug: the address parses, but yields no scriptPubKey.
        assert!(
            Address::parse(shielded_only_ua, Chain::ZcashMainnet)
                .expect("valid unified address")
                .script_pubkey()
                .is_err(),
            "fixture must be a shielded-only UA with no transparent receiver"
        );

        assert!(
            config.target_script_pubkey(shielded_only_ua).is_none(),
            "shielded-only UA must yield no transparent scriptPubKey instead of panicking"
        );
```
