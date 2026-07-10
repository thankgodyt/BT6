### Title
Unbound `refund_address` in `request_refund` Allows Any Caller to Redirect BTC Refunds to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `request_refund` function accepts a caller-supplied `refund_address` without verifying that the caller is the `deposit_msg.recipient_id` or that the `refund_address` belongs to the caller. When `deposit_msg.refund_address` is `None`, any account that knows the `deposit_msg` and the BTC transaction bytes can race the legitimate depositor to register a refund request pointing to an attacker-controlled BTC address, permanently redirecting the victim's BTC.

### Finding Description
`request_refund` is a public, permissionless function. Its only security checks are:

1. Attached NEAR storage deposit is sufficient.
2. `tx_bytes` size is within bounds.
3. If `deposit_msg.refund_address` is `Some(x)`, the provided `refund_address` must equal `x`.
4. The BTC transaction is verified via the Light Client.
5. The output script matches the deposit address derived from `deposit_msg`.
6. No duplicate refund request exists for the UTXO. [1](#0-0) 

There is **no check** that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`, and there is **no check** that `refund_address` belongs to the caller. The `refund_address` stored in the `RefundRequest` is the sole destination for the BTC refund when `execute_refund` is later called. [2](#0-1) 

The `deposit_msg` is publicly observable: `get_user_deposit_address` emits a `LogDepositAddress` event containing the full `deposit_msg`, and the `deposit_msg` also appears as a plain argument in any `verify_deposit` / `verify_deposit_v2` transaction submitted by the relayer. [3](#0-2) 

Once a refund request is registered, a duplicate is blocked: [4](#0-3) 

So the first caller wins, and the victim's subsequent `request_refund` call reverts.

The `finalize_refund_with_psbt` helper, called by `execute_refund`, builds the BTC output using `refund_request.refund_address` verbatim — the address stored at request time — with no further ownership check: [5](#0-4) [6](#0-5) 

### Impact Explanation
**Critical.** An attacker who races `request_refund` with an attacker-controlled `refund_address` causes the bridge's MPC signing pipeline to construct and broadcast a BTC transaction paying the attacker instead of the legitimate depositor. The victim's BTC is permanently lost to the attacker. This is a direct, significant theft of user funds via the bridge's refund path.

### Likelihood Explanation
**Medium.** The `deposit_msg` is observable on-chain (emitted in `LogDepositAddress` events and visible in relayer `verify_deposit` call arguments). The BTC transaction bytes and Merkle proof are public on the Bitcoin blockchain. The attacker needs only to monitor both chains and submit `request_refund` before the victim — a straightforward race on NEAR, where transaction ordering within a block is validator-controlled and there is no caller-binding on the refund address. The attacker must also pay a small NEAR storage deposit, which is a negligible barrier.

### Recommendation
1. **Bind the caller**: require `env::predecessor_account_id() == deposit_msg.recipient_id` inside `request_refund` (or its callback), so only the intended nBTC recipient can register a refund for their deposit.
2. **Alternatively, mandate `deposit_msg.refund_address`**: require that `deposit_msg.refund_address` is always `Some(...)` for refund-eligible deposits, so the BTC destination is committed at deposit-address-derivation time and cannot be overridden by a racing caller.
3. **Reject permissionless `refund_address` override**: if `deposit_msg.refund_address` is `None`, treat the refund as requiring DAO/Operator authorization rather than allowing any caller to supply an arbitrary address.

### Proof of Concept
1. Alice sends BTC to a deposit address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None, ... }`. The deposit is never finalized (e.g., the relayer fails).
2. The relayer's failed `verify_deposit` call (or Alice's prior `get_user_deposit_address` call) exposes `deposit_msg` on-chain.
3. Attacker Bob observes `deposit_msg` and the BTC transaction on the Bitcoin blockchain, constructs a valid Merkle proof, and calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "alice.near", refund_address: None },
     refund_address = "bob_btc_address",
     tx_bytes = <Alice's deposit tx>,
     vout = 0,
     proof = <valid Merkle proof>,
     gas_fee = None
   )
   ``` [7](#0-6) 
4. Bob's `request_refund_callback` passes all checks — the output script matches Alice's deposit address, the UTXO is not yet verified, and no duplicate exists — and stores a `RefundRequest` with `refund_address = "bob_btc_address"`. [8](#0-7) 
5. Alice's subsequent `request_refund` call reverts with "Refund request already exists for this UTXO".
6. After `config.unsafe_refund_timelock_sec` elapses, anyone calls `execute_refund`, and the bridge's MPC pipeline signs a BTC transaction paying Bob's address. Alice's BTC is stolen. [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L32-47)
```rust
pub struct RefundRequest {
    pub deposit_msg_json: String,
    pub utxo_storage_key: String,
    pub tx_bytes: Base64VecU8,
    pub vout: usize,
    pub amount: u128,
    pub refund_address: String,
    pub gas_fee: u128,
    pub created_at_sec: u32,
    /// Set once `execute_refund` has built a refund transaction for this request.
    /// While `true` the request is kept (not removed) so `execute_refund` can be
    /// called again to re-create the transaction (e.g. after a consensus branch
    /// change); it is removed only when the refund is finalized in
    /// `verify_refund_finalize`.
    pub executed: bool,
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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-325)
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
