### Title
Silent Failure in `sync_root_public_key_callback` Leaves `chain_signatures_root_public_key` and `change_address` Unset, Permanently Blocking All Withdrawals Until Operator Intervenes - (File: `contracts/satoshi-bridge/src/chain_signature.rs`)

---

### Summary

The bridge contract enforces that `chain_signatures_root_public_key` and `change_address` must be `None` at initialization and must be populated post-deployment via `sync_chain_signatures_root_public_key`. If the cross-contract call to the chain-signatures contract fails for any reason (e.g., the contract is not yet initialized), `sync_root_public_key_callback` silently returns `false` without setting either value and without emitting any event. Both `generate_public_key` and `get_change_script_pubkey` unconditionally panic when these fields are `None`. Any withdrawal attempt after a silent sync failure will panic during PSBT construction, leaving users' nBTC tokens stuck in the bridge until the DAO detects the failure and retries.

---

### Finding Description

**Step 1 – Enforced `None` at init.**

`Contract::new()` explicitly rejects any config that already has `chain_signatures_root_public_key` or `change_address` set:

```rust
// contracts/satoshi-bridge/src/lib.rs  lines 185-192
require!(
    config.chain_signatures_root_public_key.is_none(),
    "Init chain_signatures_root_public_key must be None"
);
require!(
    config.change_address.is_none(),
    "Init change_address must be None"
);
```

Both fields are therefore always `None` immediately after deployment.

**Step 2 – Post-deployment sync can silently fail.**

`sync_chain_signatures_root_public_key` (DAO-only) fires a cross-contract call to `chain_signatures.public_key()` and chains `sync_root_public_key_callback`. The callback silently swallows any failure:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs  lines 119-132
pub fn sync_root_public_key_callback(&mut self) -> bool {
    if let Ok(result_bytes) = env::promise_result_checked(0, MAX_PUBLIC_KEY_RESULT) {
        let root_public_key = ...;
        self.internal_mut_config().chain_signatures_root_public_key = Some(root_public_key);
        let change_address = self.generate_utxo_chain_address(...).to_string();
        self.internal_mut_config().change_address = Some(change_address);
        true
    } else {
        false   // ← silent failure: no event, no panic, both fields remain None
    }
}
```

No event is emitted on the `false` branch. The DAO receives no on-chain signal that the sync failed.

The test suite itself documents this exact failure mode:

```
// contracts/satoshi-bridge/tests/setup/context.rs  lines 1265-1267
// Initialize the mock chain-signatures contract before syncing, otherwise
// its `public_key()` panics (uninitialized) and the bridge's sync callback
// silently leaves `chain_signatures_root_public_key` unset.
```

**Step 3 – Every withdrawal panics when the fields are `None`.**

`generate_public_key` (called for every UTXO input during PSBT construction and signing) unconditionally panics:

```rust
// contracts/satoshi-bridge/src/kdf.rs  lines 30-35
pub fn generate_public_key(&self, path: &str) -> Vec<u8> {
    let mpc_pk = crypto_shared::near_public_key_to_affine_point(
        self.internal_config()
            .chain_signatures_root_public_key
            .clone()
            .expect("Missing chain_signatures_root_public_key"),  // ← panic
    );
    ...
}
```

`get_change_script_pubkey` (called to build the change output) also unconditionally panics:

```rust
// contracts/satoshi-bridge/src/config.rs  lines 160-166
pub fn get_change_script_pubkey(&self) -> ScriptBuf {
    self.string_to_script_pubkey(
        self.change_address
            .as_ref()
            .expect("ERR_CONFIG: change_address not configured"),  // ← panic
    )
}
```

`internal_sign_btc_transaction` calls `generate_btc_public_key` → `generate_public_key` for every UTXO input:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs  lines 84-88
let public_keys: Vec<_> = pending_info
    .vutxos
    .iter()
    .map(|vutxo| self.generate_btc_public_key(&vutxo.get_path()))
    .collect();
```

**Step 4 – nBTC tokens become stuck.**

The NEP-141 withdrawal flow transfers nBTC to the bridge in `ft_on_transfer` (which returns `0`, keeping the tokens) before PSBT construction begins. Because PSBT construction is a separate asynchronous step, a panic there does not roll back the token transfer. The user's nBTC remains in the bridge's balance with no automated recovery path until the DAO retries the sync and the operator manually processes the stuck withdrawal.

---

### Impact Explanation

**Medium – stuck bridge state requiring operator intervention.**

- Every user who initiates a withdrawal while `chain_signatures_root_public_key` is `None` will have their nBTC locked in the bridge contract.
- The bridge cannot process any withdrawal (signing, PSBT construction, change-output generation) until the DAO detects the silent failure and successfully retries `sync_chain_signatures_root_public_key`.
- Because no event is emitted on failure, the DAO may not detect the problem until users report failed withdrawals, potentially leaving funds stuck for an extended period.

---

### Likelihood Explanation

The test comment at `context.rs:1265-1267` explicitly identifies this as a real deployment hazard: calling `sync_chain_signatures_root_public_key` before the chain-signatures contract is fully initialized causes the callback to silently leave the key unset. This is a realistic race condition during any deployment or contract upgrade where the chain-signatures contract is redeployed or temporarily unavailable. The DAO has no on-chain signal that the sync failed, making silent failure the default outcome in that window.

---

### Recommendation

1. **Emit a failure event** in the `else` branch of `sync_root_public_key_callback` so the DAO receives an on-chain signal when the sync fails.
2. **Add a guard in `ft_on_transfer`** (or the withdrawal initiation path) that checks `chain_signatures_root_public_key.is_some()` before accepting tokens, so withdrawals are rejected cleanly (with a refund) rather than silently accepting tokens that will later be stuck.
3. **Consider panicking** in `sync_root_public_key_callback` on failure instead of returning `false`, so the DAO transaction itself fails visibly.

---

### Proof of Concept

```
1. Deploy satoshi-bridge with chain_signatures_root_public_key = None
   (enforced by new() at lib.rs:185-188).

2. DAO calls sync_chain_signatures_root_public_key() before the
   chain-signatures contract is initialized (or while it is temporarily
   unavailable).

3. sync_root_public_key_callback receives a failed promise result,
   enters the `else` branch (chain_signature.rs:129-131), returns false,
   emits no event. chain_signatures_root_public_key and change_address
   remain None.

4. DAO does not notice (no event). Bridge is opened for use.

5. User calls nbtc.ft_transfer_call(bridge_id, amount, withdraw_msg).
   ft_on_transfer returns 0 → nBTC tokens are now in bridge's balance.

6. Bridge attempts PSBT construction / signing:
   internal_sign_btc_transaction → generate_btc_public_key →
   generate_public_key → .expect("Missing chain_signatures_root_public_key")
   → PANIC.

7. The panic is in a separate NEAR transaction from the ft_transfer_call,
   so the token transfer is NOT rolled back. User's nBTC is stuck in the
   bridge until the DAO retries sync_chain_signatures_root_public_key
   and an operator manually processes the pending withdrawal.
```