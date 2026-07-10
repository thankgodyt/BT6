### Title
Unrestricted `sign_btc_transaction` with Attacker-Controlled `key_version` Permanently Corrupts Pending Withdrawal Signature Slots — (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`)

### Summary
`sign_btc_transaction` carries no caller restriction. Any unprivileged NEAR account can invoke it against any pending withdrawal, refund, or UTXO-management transaction and supply an arbitrary `key_version`. The signing callback stores the MPC-returned signature directly into the slot without verifying it against the expected public key. Once stored, the slot is permanently locked (`"Already signed"`). If the MPC service accepts a non-current key version, the stored signature is cryptographically invalid for the UTXO's script, the assembled Bitcoin transaction is unbroadcastable, and the user's nBTC remains locked in the bridge until a privileged DAO/Operator cancels the withdrawal — a capability the user does not possess.

### Finding Description

**Root cause — no caller guard on `sign_btc_transaction`:** [1](#0-0) 

The function is decorated only with `#[payable]` and `#[pause(…)]`. There is no `#[access_control_any]`, no `#[trusted_relayer]`, and no check that `env::predecessor_account_id()` matches `btc_pending_info.account_id`. Any NEAR account that attaches the MPC signing deposit can call this for any `btc_pending_sign_id`.

**Root cause — attacker-controlled `key_version` forwarded verbatim to MPC:** [2](#0-1) 

The `key_version` supplied by the caller is forwarded directly to the MPC `sign` call. The bridge never validates that `key_version` matches the version used when the UTXO's deposit address was derived.

**Root cause — callback stores signature without cryptographic verification:** [3](#0-2) 

`public_key` is derived from the UTXO path (the correct key), but the returned `signature` — which may have been produced under a different key version — is stored unconditionally into `signatures[sign_index]`. No ECDSA verification is performed to confirm the signature is valid under `public_key` before the slot is marked occupied.

**Slot permanently locked after first write:** [4](#0-3) 

The `require!(… .is_none(), "Already signed")` guard fires on any subsequent call. Once an invalid signature occupies the slot, no legitimate re-signing is possible.

**User cannot self-rescue — only DAO/Operator can cancel:** [5](#0-4) 

`cancel_withdraw` is gated behind `#[access_control_any(roles(Role::DAO, Role::Operator))]`. The affected user has no self-service path to recover their locked nBTC.

### Impact Explanation

A pending withdrawal's nBTC is already held by the bridge (transferred during `ft_on_transfer`). If an attacker corrupts one or more signature slots with a signature produced under a wrong key version, the assembled Bitcoin transaction carries an invalid witness and is rejected by the Bitcoin network on broadcast. The `BTCPendingInfo` remains in `PendingVerify` stage with no valid path to completion. The user's nBTC is stuck until a DAO or Operator calls `cancel_withdraw` to create a replacement RBF transaction. This matches the allowed Medium impact: **stuck bridge state requiring operator intervention**.

### Likelihood Explanation

Low. The attacker must:
1. Pay the MPC signing deposit (non-trivial cost).
2. Race the legitimate relayer to the unsigned slot.
3. Rely on the MPC service accepting a non-current `key_version` and returning a signature (rather than rejecting the request outright).

Key rotation is a standard MPC operational practice, making multiple valid key versions plausible on mainnet. The financial cost to the attacker is bounded by the MPC fee per input, while the cost to the victim is their entire withdrawal amount locked until operator rescue.

### Recommendation

1. **Restrict the caller** — add an ownership check inside `sign_btc_transaction`:
   ```rust
   require!(
       env::predecessor_account_id() == btc_pending_info.account_id
           || self.acl_has_role(Role::UnrestrictedRelayer.into(), env::predecessor_account_id())
           || self.data().relayer_white_list.contains(&env::predecessor_account_id()),
       "Unauthorized signer"
   );
   ```
2. **Validate `key_version`** — store the authoritative key version in `Config` and reject any call that supplies a different value.
3. **Verify the signature in the callback** — before writing to `signatures[sign_index]`, perform an ECDSA verification of the returned signature against the derived `public_key` and the `payload` that was signed; panic if it fails so the slot remains `None` and can be retried.

### Proof of Concept

```
# Attacker observes a new BTCPendingInfo for victim's withdrawal:
#   btc_pending_sign_id = "aabbcc..."
#   sign_index = 0
#   correct key_version = 0

# Attacker calls with wrong key_version (e.g., 1) while attaching MPC deposit:
near call <bridge> sign_btc_transaction \
  '{"btc_pending_sign_id":"aabbcc...","sign_index":0,"key_version":1}' \
  --accountId attacker.near --deposit 0.1

# MPC service (if it holds key v1) returns a valid-but-wrong signature.
# sign_btc_transaction_callback stores it:
#   btc_pending_info.signatures[0] = Some(<wrong-key signature>)

# Legitimate relayer now tries to sign:
near call <bridge> sign_btc_transaction \
  '{"btc_pending_sign_id":"aabbcc...","sign_index":0,"key_version":0}' \
  --accountId relayer.near --deposit 0.1
# → panics: "Already signed"

# If all slots are filled with wrong-key signatures, is_all_signed() → true,
# transaction moves to PendingVerify, is broadcast, and is rejected by Bitcoin.
# Victim's nBTC is locked; only DAO/Operator can rescue via cancel_withdraw.
```

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L95-103)
```rust
        let payload = btc_pending_info
            .get_psbt()
            .get_hash_to_sign(sign_index, &public_keys);
        let path = btc_pending_info.vutxos[sign_index].get_path();
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L144-158)
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-299)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```
