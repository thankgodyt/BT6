### Title
`sign_btc_transaction` Lacks Caller Ownership Check, Allowing Anyone to Trigger MPC Signing with Arbitrary `key_version` — (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`, `contracts/satoshi-bridge/src/chain_signature.rs`)

---

### Summary

`sign_btc_transaction` is a public, payable function that triggers an MPC chain-signature request for any `btc_pending_sign_id`. It never verifies that `env::predecessor_account_id()` is the owner of the referenced pending transaction, and it accepts a fully attacker-controlled `key_version` parameter that is forwarded verbatim to the MPC contract. This mirrors the root cause of the reported finding: a function that should only be callable by a registered/authorized entity omits the caller check, allowing anyone to invoke it with arbitrary data that is forwarded to an external contract.

---

### Finding Description

`sign_btc_transaction` in `api/chain_signatures.rs` is decorated only with `#[payable]` and `#[pause]`; there is no check that the caller owns or is authorized to act on the referenced `btc_pending_sign_id`:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();
    // ... no ownership check ...
    self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
        .into()
}
``` [1](#0-0) 

`internal_sign_btc_transaction` then forwards the attacker-supplied `key_version` directly to the MPC `sign` call:

```rust
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← fully attacker-controlled
})
.then(
    Self::ext(env::current_account_id())
        .with_static_gas(GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK)
        .sign_btc_transaction_callback(
            btc_pending_info.account_id.clone(),
            btc_pending_sign_id,
            sign_index,
        ),
)
``` [2](#0-1) 

The callback `sign_btc_transaction_callback` stores whatever signature the MPC returns, then pairs it with the **correct** public key derived from the UTXO path (not from `key_version`):

```rust
let public_key = self
    .generate_btc_public_key(
        &self.internal_unwrap_btc_pending_info(&btc_pending_sign_id)
            .vutxos[sign_index]
            .get_path(),
    )
    .inner;
// ...
btc_pending_info.signatures[sign_index] = Some(signature.clone());
// ...
psbt.save_signature(sign_index, signature, public_key);
``` [3](#0-2) 

If the MPC returns a signature produced under a different key (because `key_version` was wrong), the PSBT will contain a signature/public-key mismatch. The pending info then advances to `PendingVerifyStage`, the relayer broadcasts the transaction, and Bitcoin rejects it as invalid. The withdrawal is permanently stuck until a privileged operator intervenes.

The "Already signed" guard is checked **before** the async MPC call, not after:

```rust
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
``` [4](#0-3) 

This means two concurrent calls (attacker's and victim's) can both pass the guard simultaneously. Whichever callback lands first wins; if the attacker's wrong-`key_version` callback lands first, the slot is poisoned and the victim's callback is rejected with "Already signed".

---

### Impact Explanation

If the MPC chain-signatures contract accepts an arbitrary `key_version` and returns a signature for the corresponding derived key, an attacker can:

1. Corrupt any pending withdrawal by storing a signature produced under the wrong key.
2. Advance the pending info to `PendingVerifyStage` with an invalid signed transaction.
3. Force the Bitcoin broadcast to fail, leaving the user's nBTC locked in the bridge with no self-service recovery path.

Recovery requires a privileged `cancel_withdraw` call (DAO/Operator role), constituting a stuck bridge state requiring operator intervention.

This matches: **Medium — stuck bridge state requiring operator intervention / attacker-triggered temporary locking of bridged funds.**

---

### Likelihood Explanation

- `sign_btc_transaction` is a fully public, permissionless entry point — no role or whitelist required.
- The attacker only needs to know a victim's `btc_pending_sign_id` (observable on-chain from events emitted at pending-info creation).
- Frontrunning the victim's legitimate signing call is straightforward on NEAR (mempool visibility).
- The only cost to the attacker is the attached NEAR deposit for the MPC fee, which is modest.
- Likelihood is conditional on the MPC contract accepting non-zero `key_version` values; if it rejects them, the callback fails silently and the pending info remains in `PendingSign` state (no lasting harm). This conditionality makes the likelihood **medium**.

---

### Recommendation

Add an ownership check at the top of `sign_btc_transaction`:

```rust
let caller = env::predecessor_account_id();
require!(
    btc_pending_info.account_id == caller
        || self.acl_has_any_role(
            vec![Role::DAO.into(), Role::Operator.into(), Role::UnrestrictedRelayer.into()],
            caller
        ),
    "Not authorized to sign this transaction"
);
```

Additionally, validate `key_version` against a protocol-configured expected value before forwarding it to the MPC contract, so an attacker cannot supply an out-of-range version even if the ownership check is bypassed.

---

### Proof of Concept

1. Alice calls `ft_transfer_call` → `ft_on_transfer` → `create_btc_pending_info`. A `GenerateBtcPendingInfo` event is emitted with `btc_pending_id`.
2. Attacker observes the event and immediately calls `sign_btc_transaction(btc_pending_id, 0, 999)` with `key_version = 999`, attaching the required NEAR deposit.
3. Both Alice's and the attacker's calls pass the `signatures[0].is_none()` guard (race window before any callback returns).
4. The MPC receives two sign requests for the same payload/path but different `key_version` values.
5. The attacker's callback returns first (or is the only one that returns if Alice hasn't called yet), storing a signature produced under key version 999.
6. Alice's callback (if it arrives) panics with "Already signed".
7. `is_all_signed()` returns `true`; the pending info advances to `PendingVerifyStage` with an invalid signed transaction.
8. The relayer broadcasts the transaction; Bitcoin rejects it.
9. Alice's nBTC remains locked; only a DAO/Operator `cancel_withdraw` can recover the funds.

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-43)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L91-94)
```rust
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L99-113)
```rust
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK)
                .sign_btc_transaction_callback(
                    btc_pending_info.account_id.clone(),
                    btc_pending_sign_id,
                    sign_index,
                ),
        )
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L144-170)
```rust

            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
            let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
            btc_pending_info.last_sign_time_sec = nano_to_sec(env::block_timestamp());
            Event::BtcInputSignature {
                account_id: &account_id,
                btc_pending_id: &btc_pending_sign_id,
                sign_index,
                signature: &signature,
            }
            .emit();
            let mut psbt = btc_pending_info.get_psbt();
            psbt.save_signature(sign_index, signature, public_key);

            btc_pending_info.psbt_hex = psbt.serialize();
```
