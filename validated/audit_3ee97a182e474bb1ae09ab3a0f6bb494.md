### Title
Invalid `refund_address` Stored Without Validation Causes Permanent `execute_refund` Panic — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

When `deposit_msg.refund_address` is `None`, `request_refund` / `request_refund_callback` stores any caller-supplied `refund_address` string verbatim with no format or chain validation. `build_refund_output` later calls `Address::parse(...).expect(...)` on that string, which panics on any address that is invalid for the configured chain (wrong network, wrong format, garbage string). The refund request is then permanently stuck — `execute_refund` will always panic — and can only be cleared by DAO/Operator via `reject_refund`.

---

### Finding Description

**Entrypoint — `request_refund` (public, no `#[trusted_relayer]` on the function)**

`request_refund` is in a `#[trusted_relayer]` impl block but does **not** carry the attribute on the function itself. Functions that are individually gated (`verify_refund_finalize`, `remove_refund_pending_tx_id`) carry the attribute on the function. `execute_refund` and `request_refund` do not, consistent with the documentation "anyone can call `execute_refund`". Any NEAR account can call `request_refund`. [1](#0-0) 

**No address validation when `deposit_msg.refund_address` is `None`**

`internal_request_refund` only validates `refund_address` against `deposit_msg.refund_address` when the latter is `Some`. When it is `None`, the caller-supplied string is forwarded to the callback without any `Address::parse` check. [2](#0-1) 

**`request_refund_callback` stores the string verbatim**

The callback verifies the BTC transaction inclusion and that the output script matches the deposit address, but never validates the `refund_address` string. It stores it directly into `RefundRequest`. [3](#0-2) 

**`build_refund_output` panics on invalid address**

At execution time, `build_refund_output` calls `Address::parse(refund_address, config.chain.clone()).expect("Invalid refund address")`. If the stored string is invalid for the configured chain (e.g., a mainnet address on a testnet bridge, a Zcash address on a Bitcoin bridge, or a garbage string), this panics and the NEAR transaction is reverted. [4](#0-3) 

**Stuck state — only DAO/Operator can clear it**

After the panic, the `RefundRequest` remains in storage with `executed = false`. Every subsequent `execute_refund` call will panic identically. The only escape is `reject_refund`, which requires DAO or Operator role. [5](#0-4) 

---

### Impact Explanation

The deposit UTXO is locked: it cannot be refunded (every `execute_refund` panics) and cannot be deposited (the UTXO is not in `verified_deposit_utxo` yet). The BTC is effectively frozen until DAO/Operator manually calls `reject_refund`. This matches the Medium impact: **attacker-triggered temporary locking of bridged funds requiring operator intervention**.

An attacker targeting their own UTXO achieves this trivially. An attacker targeting another user's UTXO (whose `deposit_msg.refund_address` is `None`) can race the legitimate user's `request_refund` call — the first stored request wins, and the duplicate check blocks any subsequent one. [6](#0-5) 

---

### Likelihood Explanation

- `request_refund` is callable by any NEAR account (no role gate on the function).
- The only cost is the attached storage deposit (non-refundable, but small).
- The `unsafe_refund_timelock_sec` is a reactive mitigation: it gives DAO/Operator a window to reject suspicious requests, but requires active monitoring. If the DAO/Operator does not reject the request within the timelock, `execute_refund` will panic indefinitely. [7](#0-6) 

---

### Recommendation

Validate `refund_address` against the configured chain at storage time in `request_refund_callback` (or in `internal_request_refund` before the async call). Add a `require!` that calls `Address::parse` and rejects the request if parsing fails. This mirrors the validation already done for `change_address` in `Config::string_to_script_pubkey`. [8](#0-7) 

---

### Proof of Concept

1. Attacker calls `get_user_deposit_address` with `deposit_msg = { recipient_id: victim, refund_address: None }` — emits the `deposit_msg` as a NEAR event.
2. Attacker sends BTC to the returned deposit address.
3. Attacker calls `request_refund` with the same `deposit_msg`, `refund_address = "tb1qinvalidaddress"` (testnet bech32 on a mainnet bridge), valid `tx_bytes`, `vout`, and proof.
4. `internal_request_refund`: `deposit_msg.refund_address` is `None` → no address check → proceeds to light-client verification.
5. `request_refund_callback`: output script matches deposit address → `RefundRequest { refund_address: "tb1qinvalidaddress", ... }` stored.
6. After `unsafe_refund_timelock_sec` elapses, anyone calls `execute_refund`.
7. `build_refund_output` calls `Address::parse("tb1qinvalidaddress", Chain::BitcoinMainnet)` → `Err("Bech32 HRP mismatch: expected 'bc', got 'tb'")` → `.expect(...)` panics.
8. Every subsequent `execute_refund` call panics identically. BTC is frozen until DAO calls `reject_refund`.

### Citations

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L544-568)
```rust
    pub fn reject_refund(&mut self, utxo_storage_key: String) {
        let caller = env::predecessor_account_id();
        let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
            || self.acl_has_role(Role::Operator.into(), caller);
        // `execute_refund` also inserts the UTXO into `verified_deposit_utxo` (to block a
        // later deposit) while keeping the request with `executed == true`. That membership
        // must NOT open the permissionless reject path, otherwise anyone could cancel an
        // in-flight refund — so only treat the UTXO as "already deposited" when the request
        // was not executed by us, i.e. a real `verify_deposit` finalized it.
        let executed = self
            .data()
            .refund_requests
            .get(&utxo_storage_key)
            .map(|r| RefundRequest::from(r).executed)
            .unwrap_or(false);
        let is_already_deposited = !executed
            && self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key);
        require!(
            is_privileged || is_already_deposited,
            "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
        );
        self.internal_reject_refund(utxo_storage_key);
```

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L216-227)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
```rust
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
```

**File:** contracts/satoshi-bridge/src/config.rs (L168-175)
```rust
    pub fn string_to_script_pubkey(&self, address_string: &str) -> ScriptBuf {
        let chain = self.get_utxo_network();

        Address::parse(address_string, chain)
            .unwrap_or_else(|e| env::panic_str(&format!("{address_string}: {e}")))
            .script_pubkey()
            .expect("Failed to get script pubkey")
    }
```
