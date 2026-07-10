### Title
`VerifyDepositDetails` Event Missing `utxo_storage_key` Prevents Off-Chain Identification of Failed Deposits — (File: `contracts/satoshi-bridge/src/event.rs`)

---

### Summary

The `VerifyDepositDetails` event emitted at the end of every deposit finalization path does not include the `utxo_storage_key` (the unique on-chain identifier for a deposit UTXO). When a deposit fails — the only case where `VerifyDepositDetails` is emitted without an accompanying `UtxoAdded` event — off-chain relayers and monitoring tools have no way to correlate the failure event back to a specific UTXO. For a user with two same-amount deposits to the same recipient, the two failure events are byte-for-byte identical. A relayer that re-drives failed deposits based on these events may re-submit the wrong UTXO, leaving the other permanently unprocessed and the user's BTC/ZEC locked in the bridge address with no recovery path.

---

### Finding Description

`VerifyDepositDetails` is defined as:

```rust
VerifyDepositDetails {
    recipient_id: &'a AccountId,
    mint_amount: U128,
    protocol_fee: U128,
    relayer_account_id: AccountId,
    relayer_fee: U128,
    success: bool,
},
``` [1](#0-0) 

It carries no `utxo_storage_key`, `tx_id`, or `vout`. It is emitted unconditionally at the end of both `mint_callback` and `safe_mint_callback`:

```rust
Event::VerifyDepositDetails {
    recipient_id: &recipient_id,
    mint_amount,
    protocol_fee,
    relayer_account_id: env::signer_account_id(),
    relayer_fee,
    success: is_success,
}
.emit();
``` [2](#0-1) [3](#0-2) 

The `UtxoAdded` event — which does carry `utxo_storage_keys` — is only emitted on the **success** branch:

```rust
if is_success {
    Event::UtxoAdded {
        utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
        ...
    }.emit();
    ...
} else {
    self.data_mut()
        .verified_deposit_utxo
        .remove(&pending_utxo_info.utxo_storage_key);
}
Event::VerifyDepositDetails { ..., success: is_success }.emit();
``` [4](#0-3) 

On the failure path the UTXO key is removed from `verified_deposit_utxo`, making the UTXO eligible for re-submission. But the only emitted event (`VerifyDepositDetails { success: false }`) carries no identifier. An off-chain relayer that tracks which UTXOs need re-driving by watching this event cannot determine which UTXO to re-submit.

---

### Impact Explanation

When two deposits of equal `mint_amount` to the same `recipient_id` are in flight and one (or both) fail, the emitted `VerifyDepositDetails` events are structurally identical. An automated relayer that uses these events to schedule re-submission of failed deposits cannot distinguish UTXO A from UTXO B. It may re-submit the already-succeeded UTXO (which will panic with `"Already deposit utxo"`) while the genuinely failed UTXO is never re-driven. Because the failed UTXO's key was removed from `verified_deposit_utxo`, the BTC/ZEC sits at the bridge-controlled address indefinitely with no automated recovery path — the user's deposited funds are permanently locked unless manual operator intervention occurs.

This matches the allowed Low impact: **stuck-state in production bridge/token paths without direct theft**.

---

### Likelihood Explanation

Any user who sends two deposits of the same satoshi amount to the same `recipient_id` (a common pattern for DCA or retry-after-failure) and whose mint call fails (e.g., nBTC contract storage not registered, `ft_on_transfer` returning 0 in a `safe_deposit`, or any transient nBTC-side error) triggers the ambiguity. The failure path is reachable by any unprivileged depositor without special access. The relayer is a public, automated component that is documented to watch bridge events.

---

### Recommendation

Add `utxo_storage_key` (equivalently, `tx_id` + `vout`) to `VerifyDepositDetails` so every emission — success or failure — uniquely identifies the UTXO being finalized:

```rust
VerifyDepositDetails {
    recipient_id: &'a AccountId,
    utxo_storage_key: &'a String,   // ← add this
    mint_amount: U128,
    protocol_fee: U128,
    relayer_account_id: AccountId,
    relayer_fee: U128,
    success: bool,
},
```

Apply the same fix to `VerifyWithdrawDetails` (missing `tx_id` / `btc_pending_id`) for consistency. [5](#0-4) 

---

### Proof of Concept

1. Alice sends two BTC deposits of exactly 100 000 sats to the same `recipient_id`. The bridge derives two distinct deposit addresses; both transactions confirm on-chain, producing UTXO-A (`txA:0`) and UTXO-B (`txB:0`).
2. The relayer calls `verify_deposit` for UTXO-A. The nBTC `mint` call fails (e.g., Alice's storage is not registered). `mint_callback` removes `utxo_storage_key(txA,0)` from `verified_deposit_utxo` and emits:
   ```
   VerifyDepositDetails { recipient_id: "alice", mint_amount: 99500, ..., success: false }
   ```
   No `UtxoAdded` is emitted. [6](#0-5) 
3. The relayer calls `verify_deposit` for UTXO-B. The same failure occurs. An identical event is emitted:
   ```
   VerifyDepositDetails { recipient_id: "alice", mint_amount: 99500, ..., success: false }
   ```
4. The relayer's event-driven retry logic sees two identical failure events. It has no way to know which UTXO each corresponds to. It re-submits `verify_deposit` for UTXO-B (guessing), which succeeds this time (Alice registered storage). UTXO-A is never re-submitted.
5. UTXO-A remains absent from `verified_deposit_utxo` and absent from the bridge's UTXO set. The 100 000 sats at the UTXO-A address are permanently inaccessible — the bridge cannot spend them (no UTXO record) and the user cannot refund them (no `refund_address` was set in the `DepositMsg` for a standard `verify_deposit` flow). Alice loses 100 000 sats.

### Citations

**File:** contracts/satoshi-bridge/src/event.rs (L16-32)
```rust
    VerifyDepositDetails {
        recipient_id: &'a AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        success: bool,
    },
    VerifyWithdrawDetails {
        account_id: &'a AccountId,
        burn_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        refund: U128,
        success: bool,
    },
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L54-83)
```rust
        let is_success = is_promise_success();
        if is_success {
            if !self.check_account_exists(&recipient_id) {
                self.internal_set_account(&recipient_id, Account::new(&recipient_id));
            }
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128::from(u128::from(pending_utxo_info.utxo.balance))]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);
        }
        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee,
            relayer_account_id: env::signer_account_id(),
            relayer_fee,
            success: is_success,
        }
        .emit();
        is_success
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L458-466)
```rust
        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee: U128(0),
            relayer_account_id: env::signer_account_id(),
            relayer_fee: U128(0),
            success: is_success,
        }
        .emit();
```
