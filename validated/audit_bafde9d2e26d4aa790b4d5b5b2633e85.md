### Title
Unpermissioned `sign_btc_transaction` with Caller-Controlled `key_version` Enables Attacker-Triggered Withdrawal Stuck-State — (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

`sign_btc_transaction` carries no ownership or role check. Any NEAR account can invoke it against any pending withdrawal, and the `key_version` argument is passed verbatim to the MPC signing contract. Because the "already signed" guard permanently seals each signature slot, an attacker who races to fill a slot with a signature produced under a wrong key version leaves the assembled Bitcoin transaction permanently invalid, locking the withdrawal in `PendingVerify` state until an operator cancels it.

---

### Finding Description

`sign_btc_transaction` in `contracts/satoshi-bridge/src/api/chain_signatures.rs` is decorated only with `#[pause(except(roles(Role::DAO)))]` — no ownership check, no relayer whitelist check, no role requirement:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,          // ← fully attacker-controlled
) -> PromiseOrValue<bool> {
``` [1](#0-0) 

The function immediately delegates to `internal_sign_btc_transaction`, which forwards the caller-supplied `key_version` directly to the MPC contract:

```rust
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← no validation, taken from caller
})
``` [2](#0-1) 

The callback stores whatever signature the MPC returns and enforces a one-write-only guard:

```rust
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
btc_pending_info.signatures[sign_index] = Some(signature.clone());
``` [3](#0-2) 

Once a slot is written it can never be overwritten. If the MPC contract supports multiple key versions (e.g. after a key rotation, `key_version=1` exists), a signature produced under the wrong version is cryptographically invalid for the PSBT inputs — which were derived from the correct version — yet it is permanently stored.

When all slots are filled, the bridge assembles and stores the signed transaction bytes and advances state to `PendingVerify`:

```rust
btc_pending_info.tx_bytes_with_sign = Some(tx_bytes_with_sign);
btc_pending_info.to_pending_verify_stage();
``` [4](#0-3) 

Bitcoin will reject the broadcast because the signatures do not satisfy the input scripts. The withdrawal is now stuck in `PendingVerify` with no self-healing path; only a DAO/Operator `cancel_withdraw` can unblock it.

---

### Impact Explanation

**Medium — attacker-triggered temporary locking of bridged funds.**

A user's nBTC tokens are already held by the bridge (transferred in `ft_on_transfer`). If the attacker successfully fills all signature slots with wrong-key-version signatures before the legitimate signing infrastructure does, the assembled Bitcoin transaction is permanently invalid. The user's funds remain locked in the bridge's `PendingVerify` state until an operator manually cancels the withdrawal via `cancel_withdraw`, which itself requires a DAO/Operator role and a 1-yoctoNEAR deposit. The user cannot self-rescue.

---

### Likelihood Explanation

**Low-to-Medium.** Three conditions must hold simultaneously:

1. The MPC chain-signatures contract has been key-rotated so that `key_version ≥ 1` is a valid, accepted version (otherwise the MPC call fails and the callback returns `false` with no state change).
2. The attacker monitors the NEAR chain for newly created `BTCPendingInfo` entries (trivially done via event indexing — `Event::GenerateBtcPendingInfo` is emitted publicly).
3. The attacker front-runs the legitimate signing call for each input slot before the bridge's own signing infrastructure does.

Condition 1 is the key uncertainty from this codebase alone; conditions 2 and 3 are straightforward for an on-chain observer. The attacker must also attach enough NEAR to cover the MPC signing fee (`with_attached_deposit(env::attached_deposit())`), which is a minor economic barrier. [5](#0-4) 

---

### Recommendation

1. **Add an ownership or role check** to `sign_btc_transaction`. The simplest fix is to require the caller to be either the owner of the pending transaction (`btc_pending_info.account_id == env::predecessor_account_id()`) or a whitelisted relayer / DAO role.
2. **Validate `key_version`** against a contract-stored expected value (e.g. the current MPC key version stored in config) before forwarding it to the MPC contract, so callers cannot supply an arbitrary version.

---

### Proof of Concept

```
# 1. Alice initiates a withdrawal; bridge emits GenerateBtcPendingInfo { btc_pending_id: "abc..." }
# 2. Attacker observes the event on-chain.
# 3. Attacker calls (before the bridge's relayer does):
near call <bridge> sign_btc_transaction \
  '{"btc_pending_sign_id":"abc...","sign_index":0,"key_version":1}' \
  --deposit 0.1 --accountId attacker.near
# 4. MPC (if key_version=1 is valid) returns a signature under the rotated key.
# 5. Callback stores the invalid signature; slot 0 is now sealed.
# 6. Attacker repeats for all remaining sign_index values.
# 7. Bridge assembles tx_bytes_with_sign from all wrong-key signatures → moves to PendingVerify.
# 8. Relayer attempts to broadcast; Bitcoin rejects (invalid signatures).
# 9. Alice's nBTC is locked until DAO/Operator calls cancel_withdraw.
``` [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L64-68)
```rust
        ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
            .with_static_gas(GAS_FOR_SIGN_CALL)
            .with_attached_deposit(env::attached_deposit())
            .sign(request)
    }
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L154-158)
```rust
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L194-195)
```rust
                btc_pending_info.tx_bytes_with_sign = Some(tx_bytes_with_sign);
                btc_pending_info.to_pending_verify_stage();
```
