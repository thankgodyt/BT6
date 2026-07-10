### Title
Missing Orchard ZK Proof Verification Allows Proof-Invalid Bundle to Lock Bridge UTXOs and Burn nZEC — (`contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`)

---

### Summary

The bridge's Orchard validation path never calls `Bundle::verify_proof` at any point. Because the `BRIDGE_OVK` is a publicly known all-zeros constant, any attacker can craft a structurally valid Orchard bundle whose output is recoverable with that OVK but whose Groth16 proof is zeroed/garbage. The bundle passes every bridge check, causes nZEC to be burned and bridge UTXOs to be locked, and produces a `BTCPendingInfo` for a Zcash transaction that the Zcash network will permanently reject.

---

### Finding Description

**`BRIDGE_OVK` is public knowledge.** [1](#0-0) 

The all-zeros OVK is hardcoded and visible to any reader of the source. An attacker can use the upstream `orchard` crate to encrypt an output note to this OVK, then overwrite the bundle's proof field with arbitrary bytes before serialising.

**`extract_orchard_bundle` performs no proof verification.** [2](#0-1) 

The function calls `read_v5_bundle` (structural parse only), checks action count, and calls `recover_output_with_ovk` (symmetric AEAD decryption — no ZK check). There is no call to `Bundle::verify_proof` or any equivalent.

**`validate_orchard_bundle` also performs no proof verification.** [3](#0-2) 

It checks recipient address bytes and value balance sign/magnitude — both are structural properties derivable from the bundle fields without a valid proof.

**`check_psbt_chain_specific` is the only Orchard-specific gate in the withdrawal path, and it delegates only to `validate_orchard_bundle`.** [4](#0-3) 

**The full call chain confirms no proof check exists anywhere:**

`ft_on_transfer` → `ft_on_transfer_withdraw_chain_specific` → `ft_on_transfer_callback` [5](#0-4) 

→ `PsbtWrapper::new` → `extract_orchard_bundle` [6](#0-5) 

→ `create_btc_pending_info` → `check_withdraw_psbt_valid` → `check_withdraw_psbt` → `check_psbt_chain_specific` [7](#0-6) 

A repository-wide grep for `verify_proof`, `Bundle::verify`, `proof.verify`, and `verify_bundle` returns **zero matches**.

---

### Impact Explanation

1. The attacker burns their own nZEC (transferred via `ft_transfer_call`).
2. Bridge UTXOs are removed from the available pool and locked inside the `BTCPendingInfo`.
3. The resulting Zcash transaction — assembled in `get_zcash_tx` and serialised in `extract_tx_bytes_with_sign` — carries an invalid proof and will be permanently rejected by every Zcash full node.
4. Because the transaction can never confirm, the bridge UTXOs are permanently locked with no on-chain recovery path. [8](#0-7) 

The attacker can repeat this with different UTXO sets, progressively exhausting the bridge's spendable UTXO pool. Each attack costs only the nZEC burned (which the attacker controls) while permanently destroying bridge liquidity.

Impact classification: **Critical** — permanent locking of protocol-controlled funds (bridge UTXOs) and destruction of backed nZEC supply without a corresponding valid Zcash transaction.

---

### Likelihood Explanation

- Requires no privileged role; `ft_transfer_call` is a standard NEP-141 public entry point.
- `BRIDGE_OVK` is a compile-time constant visible in the source; constructing an OVK-recoverable output is straightforward with the upstream `orchard` crate.
- Replacing the proof bytes with zeros before serialisation is trivial.
- No economic barrier beyond owning some nZEC.

---

### Recommendation

After `extract_orchard_bundle` successfully parses and recovers the bundle, call `Bundle::verify_proof` (or the equivalent `verify` method exposed by the `orchard` crate) before accepting the bundle. This requires the Orchard verifying key to be available in the contract (or passed as a trusted parameter). If on-chain proof verification is too expensive for NEAR gas limits, the proof check must be performed by a trusted relayer before the bundle is submitted, and the contract must enforce that only verified bundles are accepted (e.g., via a relayer-signed attestation checked against an ACL).

---

### Proof of Concept

```rust
// Off-chain attacker script (pseudo-code)
let ovk = OutgoingViewingKey::from([0u8; 32]); // BRIDGE_OVK
let (bundle, _) = Builder::new(...)
    .add_recipient(bridge_orchard_addr, amount, ovk, memo)
    .build(rng, &proving_key);

// Serialise and zero out the proof field
let mut bundle_bytes = serialize_v5_bundle(&bundle);
zero_out_proof_bytes(&mut bundle_bytes); // replace Groth16 proof with 0x00…00

// Submit via ft_transfer_call
nZEC_contract.ft_transfer_call(
    bridge_account,
    amount,
    json!({ "Withdraw": {
        "target_btc_address": victim_unified_addr,
        "input": [valid_bridge_utxo],
        "output": [],
        "chain_specific_data": { "orchard_bundle_bytes": bundle_bytes, "expiry_height": H }
    }})
);

// Assert: btc_pending_infos is populated, nZEC burned
// Broadcast resulting tx to Zcash node → node rejects (invalid proof)
// Bridge UTXOs remain locked indefinitely
```

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L11-11)
```rust
pub const BRIDGE_OVK: [u8; 32] = [0u8; 32];
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L38-78)
```rust
pub fn extract_orchard_bundle(
    orchard_bundle_bytes: Option<Vec<u8>>,
    proof_size_enforcement: ProofSizeEnforcement,
) -> Result<Option<ParsedOrchardBundle>, String> {
    if let Some(orchard_bundle_bytes) = orchard_bundle_bytes {
        let mut reader = Cursor::new(orchard_bundle_bytes);
        let bundle = read_v5_bundle(&mut reader, proof_size_enforcement)
            .map_err(|_| "Failed to read orchard bundle".to_string())?
            .ok_or_else(|| "Orchard bundle is empty".to_string())?;

        // Check action count first per Orchard protocol requirements
        if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
            return Err(format!(
                "Orchard bundle must have {} actions, got {}",
                EXPECTED_ACTIONS_NUMBER,
                bundle.actions().len()
            ));
        }

        // Since we require exactly 1 action, directly recover the single output
        let ovk = orchard::keys::OutgoingViewingKey::from(BRIDGE_OVK);
        let (note, addr, _memo) = bundle
            .recover_output_with_ovk(0, &ovk)
            .ok_or_else(|| "Failed to recover Orchard output with bridge OVK".to_string())?;

        let value = note.value().inner();
        if value == 0 {
            return Err("Orchard output value must be non-zero".to_string());
        }

        Ok(Some(ParsedOrchardBundle {
            bundle,
            output: OrchardOutput {
                amount: value,
                recipient_addr: addr.to_raw_address_bytes(),
            },
        }))
    } else {
        Ok(None)
    }
}
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L86-117)
```rust
pub fn validate_orchard_bundle(
    orchard: &ParsedOrchardBundle,
    expected_recipient: &str,
    chain: &Chain,
) -> Result<(), String> {
    let recipient_address = Address::parse(expected_recipient, chain.clone())?;

    // Validate recipient
    let expected_addr_bytes = recipient_address.extract_orchard_receiver()?;
    if orchard.recipient_addr() != &expected_addr_bytes {
        return Err(format!(
            "Orchard recipient mismatch: expected {} does not match recovered output",
            expected_recipient
        ));
    }

    // Validate value balance: for withdrawal, value flows FROM transparent TO Orchard
    // So value_balance should be negative and equal to the output amount
    let value_balance = orchard.bundle.value_balance();
    let expected_value_balance =
        -i64::try_from(orchard.amount()).map_err(|_| "Orchard amount too large for i64")?;

    let actual_value_balance: i64 = (*value_balance).into();
    if actual_value_balance != expected_value_balance {
        return Err(format!(
            "Orchard value balance mismatch: expected {}, got {}. \
             Value balance must equal negative output amount for withdrawals",
            expected_value_balance, actual_value_balance
        ));
    }

    Ok(())
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L110-137)
```rust
    pub fn ft_on_transfer_callback(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        max_gas_fee: Option<U128>,
        chain_specific_data: Option<ChainSpecificData>,
        #[callback_unwrap] last_block_height: u32,
    ) -> U128 {
        let expiry_height = self.get_expiry_height(&chain_specific_data, last_block_height);
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        let psbt = PsbtWrapper::new(
            input,
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(target_btc_address.clone()),
            self.internal_config(),
        );

        self.create_btc_pending_info(sender_id, amount.0, target_btc_address, psbt, max_gas_fee);

        U128(0)
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L192-212)
```rust
    pub(crate) fn check_psbt_chain_specific(
        &self,
        psbt: &PsbtWrapper,
        gas_fee: u128,
        target_btc_address: String,
    ) {
        let min_fee = psbt.get_min_fee();
        require!(
            gas_fee >= min_fee.into_u64() as u128,
            format!(
                "Invalid gas fee ({}). min fee = {}.",
                gas_fee,
                min_fee.into_u64()
            )
        );

        // For withdrawals with Orchard bundle, calculate the expected net amount after fees
        if psbt.has_orchard_bundle() {
            psbt.validate_orchard_bundle(target_btc_address, self.internal_config().chain.clone());
        }
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L77-83)
```rust
        let orchard = orchard_policy::extract_orchard_bundle(
            orchard_bundle_bytes,
            proof_size_enforcement(get_branch_id(current_height, config)),
        )
        .unwrap_or_else(|_| {
            env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: failed to extract Orchard bundle")
        });
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L260-261)
```rust
        self.check_psbt_chain_specific(psbt, gas_fee, target_btc_address);
        (input_num, change_num, actual_received_amount, gas_fee)
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L103-133)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: sender_id.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: amount,
            actual_received_amount,
            withdraw_fee,
            gas_fee,
            burn_amount: actual_received_amount + gas_fee,
            psbt_hex,
            vutxos,
            signatures: vec![None; need_signature_num],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::WithdrawOriginal(OriginalState {
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
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```
