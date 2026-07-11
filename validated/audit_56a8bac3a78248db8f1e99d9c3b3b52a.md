Now I have all the information needed to make a definitive assessment. Let me verify the exact `execute_refund_callback` branch logic one more time to confirm the shielded rescue path.

### Title
Shielded-Only Zcash Unified Address as `refund_address` Panics in `build_refund_output`, Requiring Operator Intervention - (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` accepts any parseable Zcash address as `refund_address` with no check that it carries a transparent receiver. When `execute_refund` is later called with `chain_specific_data: None` (the transparent path), `build_refund_output` calls `Address::parse` → `script_pubkey()` → `.expect("Invalid refund script_pubkey")`, which panics for a Sapling+Orchard-only Unified Address. The refund PSBT is never built, the callback reverts, and the request remains stuck until a DAO/operator manually rescues it via the shielded path.

---

### Finding Description

**Step 1 — Attacker submits a shielded-only UA as `refund_address`.**

`request_refund` is public and payable. Its only address-related guard is:

```rust
// contracts/satoshi-bridge/src/refund.rs:154-158
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

There is no check that `refund_address` is a transparent address. A shielded-only UA (e.g. `u15a97e324mck…`) passes this guard and is stored verbatim in `RefundRequest.refund_address`. [1](#0-0) 

**Step 2 — Timelock passes; anyone calls `execute_refund` with `chain_specific_data: None`.**

`execute_refund` is public and not role-gated. On Zcash it dispatches to `execute_refund_callback`. The transparent branch is taken when no Orchard bundle is supplied:

```rust
// contracts/satoshi-bridge/src/zcash_utils/refund.rs:101-105
let output = if orchard_bundle.is_some() {
    Vec::new()
} else {
    vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
};
``` [2](#0-1) 

**Step 3 — `build_refund_output` panics.**

```rust
// contracts/satoshi-bridge/src/refund.rs:296-300
let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
    .expect("Invalid refund address");          // succeeds — UA parses fine
let refund_script_pubkey = refund_addr
    .script_pubkey()
    .expect("Invalid refund script_pubkey");    // PANICS
``` [3](#0-2) 

`Address::script_pubkey()` for a `Unified` variant iterates receivers looking for `P2pkh` or `P2sh`. A Sapling+Orchard-only UA has neither, so it falls through to:

```rust
// contracts/satoshi-bridge/src/network.rs:236
Err("No receiver found in address".to_string())
``` [4](#0-3) 

The `.expect` converts this `Err` into a panic. The callback reverts; the `RefundRequest` remains in storage.

**The codebase already documents this exact failure mode** for the withdrawal path and introduced `target_script_pubkey` (returning `Option`) as the fix — but `build_refund_output` was never updated:

```rust
// contracts/satoshi-bridge/src/config.rs:420-446 (regression comment + test)
// Regression: a Zcash unified address with no transparent receiver (shielded-only,
// e.g. Sapling+Orchard) has no scriptPubKey. `string_to_script_pubkey` panics on it
// ("Failed to get script pubkey: No receiver found in address"), which is what broke
// Orchard withdrawals to such addresses.
``` [5](#0-4) 

---

### Impact Explanation

Every call to `execute_refund(..., chain_specific_data: None)` for a refund request whose `refund_address` is a shielded-only UA panics. The UTXO is not marked verified, so the request persists, but the transparent refund path is permanently broken for that request. A DAO/operator must intervene by calling `execute_refund` with a valid Orchard bundle (`chain_specific_data: Some(...)`) to rescue the funds. This is a stuck bridge state requiring operator intervention — Medium impact.

---

### Likelihood Explanation

The scenario requires a real on-chain Zcash deposit (costs real ZEC) and a user or attacker who supplies a shielded-only UA as `refund_address`. Shielded-only UAs are common in the Zcash ecosystem (the codebase itself references a real mainnet example). The path is fully reachable by any unprivileged caller with no special knowledge beyond knowing a valid shielded-only UA string.

---

### Recommendation

Validate at `request_refund_callback` time (or at `request_refund` time) that the supplied `refund_address` yields a non-`None` `script_pubkey` when the chain is Zcash and no shielded bundle is expected. Alternatively, mirror the withdrawal-path fix: change `build_refund_output` to return `Option<TxOut>` (using `script_pubkey().ok()`) and reject or route shielded-only UAs to the Orchard path rather than panicking.

---

### Proof of Concept

1. Configure bridge for `ZcashMainnet`.
2. Make a real Zcash deposit with `deposit_msg.refund_address = Some("u15a97e324mckwx89t0ucxytpd7v3pfzey7daldrk4mwu3u55ej39f6v7myqjxw0e098hnhyp0tvfgfnxj8swt22rl4f77a8wrg9zjynh9dwj20lf232h7yzfr0v53l2s824l22l63xwlxyypnxkx9qq7dd249pj565q7490fey5czu2pm")`.
3. Call `request_refund` with the same UA as `refund_address` — succeeds (no address-format validation).
4. Wait for `refund_timelock_sec` to elapse.
5. Call `execute_refund(utxo_storage_key, chain_specific_data: None)`.
6. Observe panic: `"Invalid refund script_pubkey"` in `build_refund_output`.
7. Confirm the `RefundRequest` is still in storage; the transparent refund path is permanently broken for this UTXO without DAO intervention.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-158)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L296-300)
```rust
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L101-105)
```rust
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };
```

**File:** contracts/satoshi-bridge/src/network.rs (L214-237)
```rust
            Address::Unified { address, .. } => {
                let receiver_list = address.items_as_parsed();
                for receiver in receiver_list {
                    match receiver {
                        Receiver::P2pkh(data) => {
                            return Ok(bitcoin::ScriptBuf::new_p2pkh(
                                &PubkeyHash::from_slice(&data[..]).map_err(|err| {
                                    format!("Error on parsing Pubkey Hash: {err:?}").to_string()
                                })?,
                            ))
                        }
                        Receiver::P2sh(data) => {
                            return Ok(bitcoin::ScriptBuf::new_p2sh(
                                &ScriptHash::from_slice(&data[..]).map_err(|err| {
                                    format!("Error on parsing Script Hash: {err:?}").to_string()
                                })?,
                            ))
                        }
                        _ => {}
                    }
                }

                Err("No receiver found in address".to_string())
            }
```

**File:** contracts/satoshi-bridge/src/config.rs (L420-446)
```rust
    // Regression: a Zcash unified address with no transparent receiver (shielded-only,
    // e.g. Sapling+Orchard) has no scriptPubKey. `string_to_script_pubkey` panics on it
    // ("Failed to get script pubkey: No receiver found in address"), which is what broke
    // Orchard withdrawals to such addresses. `target_script_pubkey` must return `None`
    // for it (so the withdraw path treats transparent outputs as change) while still
    // resolving transparent addresses.
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
```
