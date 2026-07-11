### Title
Permissionless Refund Request Hijack Redirects Any User's Unfinalized BTC Deposit to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`request_refund` accepts a caller-supplied `refund_address` for any deposit UTXO without verifying that the caller is the intended recipient (`deposit_msg.recipient_id`). Because `deposit_msg` is emitted as a public NEAR event and the BTC transaction is public on-chain, any unprivileged NEAR account can submit a refund request for another user's unfinalized deposit and redirect the underlying BTC to an attacker-controlled address.

### Finding Description

`request_refund` is a public, permissionless function. Its internal callback `request_refund_callback` performs three checks before storing the refund request:

1. The BTC light-client proof is valid.
2. The transaction output's `script_pubkey` matches the deposit address derived from `deposit_msg`.
3. No duplicate refund request exists for the UTXO.

What it does **not** check is whether `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. [1](#0-0) 

The `deposit_msg` is fully public: `get_user_deposit_address` emits a `LogDepositAddress` event that includes the entire `deposit_msg` (with `recipient_id` and all optional fields). [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the caller freely supplies any BTC address as `refund_address`. The only guard is a longer `unsafe_refund_timelock_sec` (14 days by default). [3](#0-2) 

The check at lines 154–158 of `internal_request_refund` only enforces consistency *when* `deposit_msg.refund_address` is already set; it provides no protection when it is `None`. [4](#0-3) 

### Impact Explanation

An attacker who successfully registers a malicious refund request and waits out the 14-day timelock causes the MPC pipeline to sign a Bitcoin transaction that sends the victim's BTC to the attacker's address. The victim's deposit is permanently lost: `execute_refund` marks the UTXO in `verified_deposit_utxo`, blocking any subsequent `verify_deposit` call. [5](#0-4) 

This is a direct, permanent theft of user BTC — matching the **Critical** impact tier: *Significant loss, theft, destruction, or permanent locking of user or protocol funds.*

### Likelihood Explanation

- `request_refund` is callable by any NEAR account with a small attached NEAR deposit (storage fee).
- The victim's `deposit_msg` is broadcast as a public NEAR event the moment they call `get_user_deposit_address`.
- Even without the event, the `deposit_msg` for a standard deposit is trivially guessable: `{"recipient_id":"<victim>.near"}`.
- The attack targets deposits that were never finalized (relayer downtime, user error) — exactly the scenario the refund system is designed for.
- The DAO can reject the request within 14 days, but this is an operational mitigation that requires continuous monitoring and correct identification of malicious requests among legitimate ones.

### Recommendation

Add an ownership check in `request_refund_callback` (or in `internal_request_refund` before the async call) that enforces:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.recipient_id,
    "Only the deposit recipient may request a refund"
);
```

Alternatively, require that `deposit_msg.refund_address` is pre-set (non-`None`) for any permissionless refund request, and restrict caller-supplied `refund_address` to DAO/Operator roles only.

### Proof of Concept

1. **Alice** calls `get_user_deposit_address({ recipient_id: "alice.near", refund_address: None })`. The NEAR event `LogDepositAddress` is emitted, exposing her full `deposit_msg`.
2. Alice sends 1 BTC to the returned deposit address. The relayer goes offline; `verify_deposit` is never called.
3. **Bob** reads Alice's `deposit_msg` from the NEAR event log and her BTC transaction from the Bitcoin blockchain.
4. Bob calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "alice.near" },
     refund_address = "bc1q<bob_address>",
     tx_bytes = <alice's BTC tx>,
     vout = 0,
     proof = <valid merkle proof>
   )
   ```
   with the required NEAR storage deposit attached.
5. `request_refund_callback` verifies the light-client proof ✓, verifies the output script matches Alice's deposit address ✓, finds no duplicate ✓ — and stores `RefundRequest { refund_address: "bc1q<bob_address>", ... }`. No check that Bob ≠ Alice's `recipient_id`. [6](#0-5) 

6. After `unsafe_refund_timelock_sec` (14 days) elapses, Bob (or anyone) calls `execute_refund(utxo_storage_key)`.
7. The MPC pipeline signs a Bitcoin transaction paying 1 BTC (minus gas fee) to Bob's address. [7](#0-6) 

8. Alice's BTC is permanently redirected to Bob. The UTXO is marked in `verified_deposit_utxo`, so Alice can never recover via `verify_deposit`.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

```

**File:** contracts/satoshi-bridge/src/refund.rs (L497-548)
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

```

**File:** contracts/satoshi-bridge/src/refund.rs (L563-578)
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

**File:** contracts/satoshi-bridge/src/config.rs (L116-118)
```rust
    // Timelock for refunds where the refund address comes from the request caller
    // (`deposit_msg.refund_address` was None). Must be >= `refund_timelock_sec`.
    pub unsafe_refund_timelock_sec: u64,
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L18-44)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        _chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
    }
```
