### Title
Asymmetric Orchard-Bundle Encoding in `PsbtWrapper::to_bytes` vs `PsbtWrapper::deserialize` Permanently Locks Zcash Withdrawal and Refund Funds - (File: `contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs`)

---

### Summary

`PsbtWrapper::to_bytes()` and `PsbtWrapper::deserialize()` are asymmetric in how they encode the "no Orchard bundle" case. The serializer writes a single `[0x00]` byte when `orchard` is `None`, but the deserializer unconditionally calls `read_v5_bundle` (which expects a 4-byte `u32` action count). This misalignment causes a panic or corrupt field reads during every transparent Zcash withdrawal, transparent refund, and active-UTXO-management signing step, permanently locking user funds in the bridge.

---

### Finding Description

**Serializer (`to_bytes`, lines 248–260):**

```rust
if let Some(orchard) = &self.orchard {
    zcash_primitives::transaction::components::orchard::write_v5_bundle(
        Some(&orchard.bundle), &mut buf,
    ).unwrap();
    buf.write_all(&[1u8; 1]).unwrap();
    buf.write_all(&orchard.output.amount.to_le_bytes()).unwrap();
    buf.write_all(&orchard.output.recipient_addr).unwrap();
} else {
    buf.write_all(&[0u8; 1]).unwrap();   // ← writes exactly 1 byte
}
```

When `orchard` is `None`, `to_bytes()` writes a single `0x00` byte and does **not** call `write_v5_bundle`. [1](#0-0) 

**Deserializer (`deserialize`, lines 336–371):**

```rust
let orchard_bundle = if version >= 3 {
    read_v5_bundle(&mut rdr, proof_size_enforcement(branch_id))
        .unwrap_or_else(|_| env::panic_str("ERR_INVALID_PSBT: failed to read Orchard bundle"))
} else {
    None
};
```

Because `to_bytes()` always writes `version = 3`, the deserializer **always** calls `read_v5_bundle`. The `read_v5_bundle` function (from `zcash_primitives`) reads a `u32` (4 bytes) for the action count. But the serializer only wrote 1 byte (`0x00`) for the None case. [2](#0-1) 

**Byte-level mismatch:**

| Case | `to_bytes()` writes | `deserialize()` reads |
|---|---|---|
| `orchard = Some(b)` | `write_v5_bundle(Some(b))` + `[1u8]` + amount + addr | `read_v5_bundle` (4-byte u32 action count) + flag + amount + addr |
| `orchard = None` | `[0x00]` (1 byte) | `read_v5_bundle` tries to consume 4 bytes |

When `orchard = None` and `recipient_address = Some(addr)`, `read_v5_bundle` reads `[0x00, 0x01, len_lo, len_hi]` as a non-zero action count and then tries to parse that many Orchard actions from the remaining bytes — causing a panic via `unwrap_or_else(|_| env::panic_str(...))`.

When `orchard = None` and `recipient_address = None`, `read_v5_bundle` reads `[0x00, 0x00, 0x00, 0x00]` = 0 actions and returns `None`, but the stream cursor is now 3 bytes ahead of where it should be, causing the subsequent `recipient_address` flag read to consume garbage bytes.

**Confirmed reachable `orchard = None` paths:**

1. **Transparent Zcash withdrawal** — `ft_on_transfer_callback` sets `orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0)`. When a user passes `chain_specific_data: None`, `orchard_bundle = None`. [3](#0-2) 

2. **Transparent Zcash refund** — `execute_refund_callback` sets `orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0)`. When `chain_specific_data = None`, `orchard_bundle = None`. [4](#0-3) 

3. **Active UTXO management** — `active_utxo_management_callback` hardcodes `orchard_bundle_bytes = None`. [5](#0-4) 

In all three cases, the resulting `PsbtWrapper` is serialized via `serialize()` → `to_bytes()` and stored in `BTCPendingInfo.psbt_hex`. Later, `get_psbt()` calls `PsbtWrapper::deserialize(&self.psbt_hex)`, which panics. [6](#0-5) 

---

### Impact Explanation

When `sign_btc_transaction` (or any callback that calls `get_psbt()`) is invoked for a transparent Zcash withdrawal or refund, the contract panics. The user's nZEC tokens have already been transferred to the bridge via `ft_transfer_call`, and the underlying ZEC UTXOs are reserved. Because the PSBT can never be deserialized, the signing step can never complete, the transaction can never be broadcast, and the funds are permanently locked. This matches: **Critical — significant permanent locking of user or protocol funds** and **Medium — stuck bridge state requiring operator intervention**.

---

### Likelihood Explanation

Any Zcash user performing a transparent (non-Orchard) withdrawal or refund triggers this path. The `chain_specific_data: None` case is explicitly documented and tested as a valid transparent-refund flow (`test_zcash_refund_transparent`). The bug fires on every such operation without any special attacker knowledge. [7](#0-6) 

---

### Recommendation

In `to_bytes()`, replace the bare `[0u8]` write with a proper `write_v5_bundle(None, &mut buf)` call so the serializer and deserializer use the same encoding for the absent-bundle case:

```rust
// Before (broken):
} else {
    buf.write_all(&[0u8; 1]).unwrap();
}

// After (fixed):
} else {
    zcash_primitives::transaction::components::orchard::write_v5_bundle(
        None, &mut buf,
    ).unwrap();
    buf.write_all(&[0u8; 1]).unwrap(); // is_some flag = 0, no output metadata
}
```

Alternatively, add a version-gated presence flag before the bundle bytes in `to_bytes()` and mirror it in `deserialize()`, so the deserializer only calls `read_v5_bundle` when the flag indicates a bundle is present.

---

### Proof of Concept

1. Deploy the Zcash bridge contract.
2. Deposit ZEC to obtain a UTXO.
3. Call `ft_transfer_call` with `chain_specific_data: None` and a valid transparent output (transparent withdrawal).
4. `ft_on_transfer_callback` creates `PsbtWrapper` with `orchard = None`, calls `serialize()` → `to_bytes()` → writes `[0x00]` for the orchard section, stores hex in `BTCPendingInfo`.
5. Call `sign_btc_transaction` for the pending tx.
6. `sign_btc_transaction` calls `btc_pending_info.get_psbt()` → `PsbtWrapper::deserialize()` → `read_v5_bundle` reads `[0x00, 0x01, ...]` as a non-zero action count → panics with `ERR_INVALID_PSBT: failed to read Orchard bundle`.
7. The pending info remains in storage forever; the user's nZEC and the ZEC UTXO are permanently locked. [1](#0-0) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L215-260)
```rust
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::<u8>::new();
        let version: u8 = 3;
        buf.push(version);
        match self.branch_id {
            BranchId::Nu6 => buf.write_all(&[7u8; 1]).unwrap(),
            BranchId::Nu6_1 => buf.write_all(&[8u8; 1]).unwrap(),
            BranchId::Nu6_2 => buf.write_all(&[9u8; 1]).unwrap(),
            _ => unreachable!(),
        }
        buf.write_all(&self.expiry_height.to_le_bytes()).unwrap();

        let len = self.vin.len() as u64;
        buf.write_all(&len.to_le_bytes()).unwrap();

        for t in self.vin.clone() {
            t.write(&mut buf).unwrap();
        }

        let len = self.vout.len() as u64;
        buf.write_all(&len.to_le_bytes()).unwrap();

        for t in self.vout.clone() {
            t.write(&mut buf).unwrap();
        }

        let len = self.inputs_utxo.len() as u64;
        buf.write_all(&len.to_le_bytes()).unwrap();

        for t in self.inputs_utxo.clone() {
            t.write(&mut buf).unwrap();
        }

        if let Some(orchard) = &self.orchard {
            zcash_primitives::transaction::components::orchard::write_v5_bundle(
                Some(&orchard.bundle),
                &mut buf,
            )
            .unwrap();

            buf.write_all(&[1u8; 1]).unwrap();
            buf.write_all(&orchard.output.amount.to_le_bytes()).unwrap();
            buf.write_all(&orchard.output.recipient_addr).unwrap();
        } else {
            buf.write_all(&[0u8; 1]).unwrap();
        }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L336-371)
```rust
        let orchard_bundle = if version >= 3 {
            read_v5_bundle(&mut rdr, proof_size_enforcement(branch_id)).unwrap_or_else(|_| {
                env::panic_str("ERR_INVALID_PSBT: failed to read Orchard bundle")
            })
        } else {
            None
        };

        let orchard = if let Some(orchard_bundle) = orchard_bundle {
            let is_some = read_u8(&mut rdr).unwrap_or_else(|_| {
                env::panic_str("ERR_INVALID_PSBT: failed to read orchard_output flag")
            });
            if is_some == 1 {
                let amount = read_u64_le(&mut rdr).unwrap_or_else(|_| {
                    env::panic_str("ERR_INVALID_PSBT: failed to read orchard amount")
                });
                let mut addr = [0u8; ORCHARD_RAW_ADDRESS_SIZE];
                for addr_byte in &mut addr {
                    *addr_byte = read_u8(&mut rdr).unwrap_or_else(|_| {
                        env::panic_str("ERR_INVALID_PSBT: failed to read orchard address")
                    });
                }

                Some(ParsedOrchardBundle {
                    bundle: orchard_bundle,
                    output: OrchardOutput {
                        amount,
                        recipient_addr: addr,
                    },
                })
            } else {
                None
            }
        } else {
            None
        };
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L122-134)
```rust
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
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L152-162)
```rust
        let psbt = PsbtWrapper::new(
            input,
            output,
            None,
            expiry_height,
            last_block_height,
            None,
            self.internal_config(),
        );

        self.create_active_utxo_management_pending_info(account_id, psbt);
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L97-115)
```rust
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        // Shielded refund routes funds through the Orchard bundle (no transparent
        // output); transparent refund pays a single t-address output.
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };

        let mut psbt = PsbtWrapper::new(
            vec![outpoint],
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(refund_request.refund_address.clone()),
            self.internal_config(),
        );
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L303-305)
```rust
    pub fn get_psbt(&self) -> PsbtWrapper {
        PsbtWrapper::deserialize(&self.psbt_hex)
    }
```
