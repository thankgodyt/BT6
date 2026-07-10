Looking at the exact production code path, I need to verify:
1. Whether `request_refund_callback` validates `refund_address` format
2. Whether `build_refund_output` panics on invalid addresses
3. Whether `request_refund` is publicly callable

**Step 1 — `request_refund_callback` address validation:**

The callback's only check involving script_pubkey is: [1](#0-0) 

This verifies the **deposit** output's script_pubkey matches the deposit address derived from `deposit_msg`. The `refund_address` parameter is stored directly with zero format validation: [2](#0-1) 

**Step 2 — `build_refund_output` panics on invalid address:** [3](#0-2) 

`Address::parse` returns `Err` for any non-parseable string, and `.expect("Invalid refund address")` panics. On Bitcoin this is called synchronously before any state mutation: [4](#0-3) 

On Zcash (transparent path), same panic occurs inside `execute_refund_callback`: [5](#0-4) 

**Step 3 — `request_refund` and `execute_refund` are publicly callable:**

Both sit in a `#[trusted_relayer] impl` block, but neither method carries a method-level `#[trusted_relayer]` attribute. Comparing with `verify_refund_finalize` and `remove_refund_pending_tx_id` which explicitly carry `#[trusted_relayer]` on the method, the pattern is clear: the impl-level attribute does not auto-apply; only methods with the explicit method-level attribute are gated. `request_refund` and `execute_refund` are only gated by `#[pause]`: [6](#0-5) [7](#0-6) 

**Step 4 — One request per UTXO blocks the legitimate user:** [8](#0-7) 

An attacker who front-runs with a garbage `refund_address` occupies the slot; the legitimate depositor cannot submit their own request.

**Step 5 — State after panic:**

The panic reverts the NEAR transaction. `finalize_refund_with_psbt` (which sets `executed = true` and inserts into `verified_deposit_utxo`) is never reached. The `refund_requests` entry remains with `executed = false` and an unparseable `refund_address`, permanently blocking `execute_refund`.

---

### Title
Unvalidated `refund_address` in `request_refund_callback` causes `execute_refund` to panic and permanently locks deposit UTXOs — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
`request_refund_callback` stores any arbitrary string as `refund_address` without calling `Address::parse`. When `execute_refund` later calls `build_refund_output`, `Address::parse(...).expect("Invalid refund address")` panics, reverting the transaction while leaving the request in `refund_requests`. Because only one request per UTXO is allowed, the deposit UTXO is permanently stuck until DAO/Operator calls `reject_refund`.

### Finding Description
`request_refund` and `execute_refund` are publicly callable (no method-level `#[trusted_relayer]`). An attacker who observes an unverified deposit UTXO on-chain can call `request_refund` with a syntactically invalid `refund_address` (e.g., `"garbage"`). The light-client proof verifies the deposit transaction, and `request_refund_callback` stores the request after checking only that the deposit output's `script_pubkey` matches the deposit address — the `refund_address` field is never validated. After the timelock elapses, every call to `execute_refund` panics inside `build_refund_output` at `.expect("Invalid refund address")`. The NEAR transaction reverts, the `refund_requests` entry is unchanged, and the duplicate-request guard prevents the legitimate depositor from submitting a corrected request.

### Impact Explanation
The deposit UTXO is locked in `refund_requests` with an unparseable address. `execute_refund` will always panic. The only recovery path is for DAO/Operator to call `reject_refund`, after which a new valid `request_refund` can be submitted. This matches the Medium scoped impact: attacker-triggered temporary locking of bridged funds requiring operator intervention.

### Likelihood Explanation
The attack requires: (a) paying `required_balance_for_request_refund()` in NEAR (non-refundable anti-spam fee), and (b) a valid BTC transaction proof for an unverified deposit UTXO. Both are achievable by any on-chain observer. The cost is low relative to the disruption caused.

### Recommendation
Validate `refund_address` with `Address::parse` inside `request_refund_callback` before storing the request, and return `false` (or `require!` with a descriptive message) if parsing fails. This ensures only addresses that `build_refund_output` can later process are ever stored.

### Proof of Concept
1. Observe an unverified deposit UTXO `txid:vout` on Bitcoin.
2. Call `request_refund(deposit_msg, "garbage_address", tx_bytes, vout, proof, None)` with sufficient attached NEAR.
3. `request_refund_callback` passes (deposit script_pubkey check is unrelated to `refund_address`); the request is stored with `refund_address = "garbage_address"`.
4. Wait for `config.unsafe_refund_timelock_sec` to elapse.
5. Call `execute_refund("txid@vout", None)`.
6. `build_refund_output` calls `Address::parse("garbage_address", chain).expect(...)` → panic → transaction reverts.
7. Assert `refund_requests` still contains the entry; assert `execute_refund` continues to panic on every subsequent call.
8. The legitimate depositor's call to `request_refund` with a valid address is rejected: `"Refund request already exists for this UTXO"`.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L294-300)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L24-31)
```rust
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L101-105)
```rust
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };
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
