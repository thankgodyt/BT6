### Title
Anyone Can Submit a Refund Request with Arbitrary BTC Destination Address - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
`request_refund()` is publicly callable by any NEAR account. When the original `deposit_msg.refund_address` is `None`, the caller-supplied `refund_address` parameter is stored verbatim with no check that the caller is the deposit owner. An attacker who observes a deposit on-chain can front-run or race the legitimate user by submitting a refund request pointing to an attacker-controlled BTC address, and after the `unsafe_refund_timelock_sec` elapses (if DAO/Operator fails to reject), call `execute_refund` to drain the UTXO to their own address.

### Finding Description

`request_refund` sits inside a `#[trusted_relayer]` impl block but carries no `#[trusted_relayer]` attribute of its own: [1](#0-0) 

The function only checks `#[payable]` and `#[pause]`. The test suite explicitly confirms that `verify_deposit`, `safe_verify_deposit`, `verify_withdraw`, and `verify_active_utxo_management` all reject unauthorized callers with "Relayer is not active", but `request_refund` is conspicuously absent from that test — consistent with the doc comment "Anyone who knows the deposit_msg can request a refund." [2](#0-1) 

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [3](#0-2) 

When `deposit_msg.refund_address` is `None` (the branch is simply skipped), the caller-supplied `refund_address` is stored directly into the `RefundRequest` with no ownership check: [4](#0-3) 

The `deposit_msg` needed to construct the call is fully public — it is emitted on-chain by `get_user_deposit_address` via `Event::LogDepositAddress`: [5](#0-4) 

The `request_refund_callback` only verifies that the transaction output script matches the deposit address derived from `deposit_msg`; it does not verify the caller's identity or the legitimacy of `refund_address`: [6](#0-5) 

After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is also callable by anyone: [7](#0-6) 

The longer timelock for the no-`refund_address` case is the only mitigation, explicitly acknowledged in the code: [8](#0-7) 

### Impact Explanation

If DAO/Operator does not reject the attacker's request within `unsafe_refund_timelock_sec`, `execute_refund` builds a PSBT paying the attacker's BTC address and submits it to MPC for signing. The signed transaction is broadcast to Bitcoin/Zcash, permanently transferring the victim's deposited UTXO to the attacker. The victim's BTC/ZEC is irreversibly lost. This matches **Critical — significant loss of user funds**.

### Likelihood Explanation

The attack requires:
1. A deposit where `deposit_msg.refund_address` is `None` (common — the field is optional and many users omit it).
2. `verify_deposit` not yet called for that UTXO (the deposit is unfinalized).
3. DAO/Operator failing to reject within `unsafe_refund_timelock_sec`.

All three conditions are realistic. The `deposit_msg` is public on-chain. The attacker only loses the small anti-spam NEAR deposit if rejected. A single inattentive monitoring window is sufficient for the attack to succeed.

### Recommendation

Add an ownership check in `request_refund` when `deposit_msg.refund_address` is `None`. Require `env::predecessor_account_id() == deposit_msg.recipient_id` (or a pre-authorized delegate) before accepting a caller-supplied `refund_address`. Alternatively, when `deposit_msg.refund_address` is `None`, disallow third-party callers entirely and require the deposit owner to supply the refund address directly.

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: "alice", refund_address: None, ... })`. The event `LogDepositAddress` is emitted on-chain with the full `deposit_msg`.
2. Alice sends BTC to the returned address. `verify_deposit` is not called (relayer is down or delayed).
3. Attacker observes the `LogDepositAddress` event and the BTC transaction on-chain.
4. Attacker calls `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)` with the correct `deposit_msg` (copied from the event) and their own BTC address. The call succeeds because `deposit_msg.refund_address` is `None` — the guard at `refund.rs:154-158` is skipped.
5. `request_refund_callback` verifies the transaction inclusion and stores `RefundRequest { refund_address: "attacker_btc_addr", ... }`.
6. DAO/Operator does not notice or does not reject within `unsafe_refund_timelock_sec`.
7. Attacker calls `execute_refund(utxo_storage_key)`. The PSBT is built paying `"attacker_btc_addr"` and submitted to MPC.
8. The signed transaction is broadcast; Alice's BTC is permanently transferred to the attacker.

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L516-525)
```rust
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
