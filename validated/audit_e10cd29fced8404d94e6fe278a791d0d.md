### Title
Out-of-bounds `sign_index` causes reachable panic in `sign_btc_transaction` — (`contracts/satoshi-bridge/src/chain_signature.rs`)

### Summary

`sign_btc_transaction` is a public, unpermissioned entry point. It passes the caller-supplied `sign_index` directly into `btc_pending_info.signatures[sign_index]` without a bounds check, causing a Rust index-out-of-bounds panic when `sign_index >= signatures.len()`. The panic is real and reachable. However, the claimed impact — **permanent locking of `BTCPendingInfo`** — does not materialise: NEAR reverts all state on panic, so the pending info is left intact and legitimate signers are unaffected.

---

### Finding Description

`sign_btc_transaction` in `api/chain_signatures.rs` carries no role guard — only `#[pause(except(roles(Role::DAO)))]`, which controls whether the function is paused, not who may call it. [1](#0-0) 

It delegates immediately to `internal_sign_btc_transaction`, which performs an unchecked vector index at line 92:

```rust
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
``` [2](#0-1) 

`signatures` is a `Vec<Option<SignatureResponse>>` whose length equals the number of UTXO inputs in the pending transaction. [3](#0-2) 

Any caller who knows a valid `btc_pending_sign_id` (enumerable via the public view `get_btc_pending_infos_paged`) can supply `sign_index = signatures.len()` or any larger value and trigger a Rust panic before any cross-contract call is dispatched.

The same unchecked access recurs at line 98 (`vutxos[sign_index]`) and inside `sign_btc_transaction_callback` at lines 149 and 155–158, but those are only reachable after the initial call succeeds. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

**Claimed impact is incorrect.** NEAR's execution model reverts all storage writes when a contract panics. Because the panic fires at line 92 — before `sign_promise` is ever dispatched — no cross-contract call is scheduled and no state is mutated. The `BTCPendingInfo` is **not** permanently locked; it remains in `PendingSign` state and legitimate callers can sign it normally on the next call.

The real impact is:

- A publicly reachable panic / invariant violation in a production bridge path.
- The attacker's own transaction fails and is reverted; they lose attached gas/NEAR.
- No funds are locked, stolen, or destroyed.

This maps to: **Low — publicly reachable panic-driven fault in production bridge/token paths without direct theft.**

---

### Likelihood Explanation

Any account that can observe a pending sign ID (public view function) and submit a transaction can trigger the panic. No privilege, leaked key, or special role is required. Likelihood is high that the code path is reachable, but the absence of lasting state damage keeps overall severity Low.

---

### Recommendation

Add an explicit bounds check before indexing:

```rust
require!(
    sign_index < btc_pending_info.signatures.len(),
    "sign_index out of range"
);
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
```

Apply the same guard before `vutxos[sign_index]` at line 98 and at the top of `sign_btc_transaction_callback` before lines 149 and 155. [6](#0-5) 

---

### Proof of Concept

1. Observe a live `btc_pending_sign_id` via `get_btc_pending_infos_paged`; note that the pending info has `N` inputs (e.g. `N = 1`).
2. Call `sign_btc_transaction(btc_pending_sign_id, sign_index = N, key_version = 0)` with any attached deposit.
3. The contract panics at `signatures[N]` (index out of bounds); the transaction is reverted.
4. Call `sign_btc_transaction(btc_pending_sign_id, sign_index = 0, key_version = 0)` — succeeds normally, proving no permanent lock occurred.

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-26)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L76-113)
```rust
    pub fn internal_sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> Promise {
        let pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);

        let public_keys: Vec<_> = pending_info
            .vutxos
            .iter()
            .map(|vutxo| self.generate_btc_public_key(&vutxo.get_path()))
            .collect();

        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
        let payload = btc_pending_info
            .get_psbt()
            .get_hash_to_sign(sign_index, &public_keys);
        let path = btc_pending_info.vutxos[sign_index].get_path();
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L145-158)
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
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L121-123)
```rust
    pub vutxos: Vec<VUTXO>,
    pub signatures: Vec<Option<SignatureResponse>>,
    pub tx_bytes_with_sign: Option<Vec<u8>>,
```
