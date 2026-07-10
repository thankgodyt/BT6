Now I have all the code I need. Let me trace the exact path.

### Title
Unvalidated `refund_address` stored in `request_refund_callback` causes `execute_refund` to panic, requiring operator intervention — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

`request_refund` and its callback store the caller-supplied `refund_address` string without any format validation. `execute_refund` later calls `build_refund_output`, which calls `Address::parse(...).expect("Invalid refund address")` and panics on an invalid string. The NEAR transaction reverts, leaving the refund request permanently stuck in `refund_requests` until a DAO/Operator calls `reject_refund`.

---

### Finding Description

**Step 1 — `request_refund` accepts any `refund_address` string.**

In `internal_request_refund`, the only check on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None` (the common case where the user did not pre-authorize an address), **any string is accepted** — including garbage, a wrong-network address, or a completely unparseable value.

**Step 2 — `request_refund_callback` stores the address without validation.**

The `script_pubkey` equality check in the callback verifies that the **deposit transaction output** at `vout` matches the deposit address derived from `deposit_msg`. It has nothing to do with `refund_address`:

```rust
require!(
    deposit_script_pubkey == output.script_pubkey,
    "Output script_pubkey does not match deposit address"
);
``` [2](#0-1) 

After this check passes, `refund_address` is stored verbatim in the `RefundRequest` with no format validation: [3](#0-2) 

**Step 3 — `execute_refund` panics on the invalid address.**

`internal_execute_refund` (Bitcoin path) calls `build_refund_output` directly: [4](#0-3) 

`build_refund_output` calls `Address::parse` with `.expect`:

```rust
let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
    .expect("Invalid refund address");
``` [5](#0-4) 

`Address::parse` returns `Err` for any string that is not a valid Bech32 SegWit, Base58Check P2PKH/P2SH, or Zcash address on the configured chain: [6](#0-5) 

The `.expect` converts that `Err` into a NEAR panic, reverting the entire transaction. The `RefundRequest` remains in `refund_requests` with `executed = false`.

**Step 4 — Duplicate guard blocks a corrective request.**

While the bad request exists, the duplicate guard in `request_refund_callback` prevents any new request for the same UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [7](#0-6) 

The only escape is a privileged `reject_refund` call.

---

### Impact Explanation

The deposit UTXO is controlled by the bridge's MPC key on Bitcoin. With a stuck refund request, `execute_refund` always panics and no new request can be submitted. The BTC is not destroyed, but it is inaccessible to the user until a DAO/Operator calls `reject_refund` to clear the poisoned entry. This matches the **Medium** scope: *attacker-triggered temporary locking of bridged funds requiring operator intervention*.

---

### Likelihood Explanation

- `request_refund` is a public, payable function — any account can call it for any deposit UTXO whose `deposit_msg` is known (emitted via `LogDepositAddress` events on-chain).
- The attacker only needs to pay the storage deposit (`required_balance_for_request_refund`) and submit before the legitimate owner.
- No privileged role is required.
- The Zcash path (`execute_refund_callback`) also calls `build_refund_output` for transparent refunds, so both chains are affected. [8](#0-7) 

---

### Recommendation

Validate `refund_address` with `Address::parse` at the point of storage — inside `request_refund_callback` — and `require!` it succeeds before inserting the `RefundRequest`. This is a one-line guard:

```rust
crate::network::Address::parse(&refund_address, config.chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

Place it immediately after the `deposit_script_pubkey == output.script_pubkey` check, before the `RefundRequest` is constructed. [9](#0-8) 

---

### Proof of Concept

```
1. Attacker observes a deposit UTXO on Bitcoin for which deposit_msg.refund_address is None.
2. Attacker calls request_refund(deposit_msg, "NOT_A_VALID_ADDRESS", tx_bytes, vout, proof, None)
   with the required storage deposit attached.
3. Light-client verification passes (the tx is real); request_refund_callback stores the
   RefundRequest with refund_address = "NOT_A_VALID_ADDRESS".
4. Legitimate owner cannot submit their own request — duplicate guard fires.
5. After unsafe_refund_timelock_sec elapses, anyone calls execute_refund(utxo_storage_key, None).
6. build_refund_output calls Address::parse("NOT_A_VALID_ADDRESS", chain).expect(...) → PANIC.
7. Transaction reverts; RefundRequest remains in refund_requests with executed = false.
8. execute_refund can never succeed; DAO/Operator must call reject_refund to unblock.
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L296-297)
```rust
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L497-580)
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L30-30)
```rust
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);
```

**File:** contracts/satoshi-bridge/src/network.rs (L152-206)
```rust
    pub fn parse(address: &str, chain: Chain) -> Result<Self, String> {
        if chain == Chain::ZcashMainnet || chain == Chain::ZcashTestnet {
            let addr = ZcashAddress::try_from_encoded(address)
                .map_err(|e| format!("Error on parsing ZCash Address: {e}"))?;

            let network = match chain {
                Chain::ZcashMainnet => zcash_protocol::consensus::NetworkType::Main,
                Chain::ZcashTestnet => zcash_protocol::consensus::NetworkType::Test,
                _ => unreachable!(),
            };

            return addr
                .convert_if_network::<Self>(network)
                .map_err(|e| e.to_string());
        }

        if let Some(hrp) = get_segwit_hrp(&chain) {
            if let Ok((decoded_hrp, witness_version, data)) = bech32::segwit::decode(address) {
                let expected_hrp =
                    Hrp::parse(hrp).map_err(|e| format!("Invalid expected HRP '{hrp}': {e}"))?;
                if expected_hrp != decoded_hrp {
                    return Err(format!(
                        "Bech32 HRP mismatch: expected '{hrp}', got '{decoded_hrp}'"
                    ));
                }

                let version =
                    WitnessVersion::try_from(witness_version).map_err(|err| format!("{err:?}"))?;
                let program = WitnessProgram::new(version, &data).map_err(|err| {
                    format!("bech32 guarantees valid program length for witness: {err:?}")
                })?;

                return Ok(Address::Segwit { program, chain });
            }
        }

        let data = bitcoin::base58::decode_check(address)
            .map_err(|e| format!("Base58 decode error: {e}"))?;

        let prefix = get_pubkey_address_prefix(&chain);
        if data.starts_with(&prefix) {
            let hash = PubkeyHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid pubkey hash: {e}"))?;
            return Ok(Address::P2pkh { hash, chain });
        }

        let prefix = get_script_address_prefix(&chain);
        if data.starts_with(&prefix) {
            let hash = ScriptHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid script hash: {e}"))?;
            return Ok(Address::P2sh { hash, chain });
        }

        Err("Unknown address format or unsupported chain".to_string())
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L101-105)
```rust
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };
```
