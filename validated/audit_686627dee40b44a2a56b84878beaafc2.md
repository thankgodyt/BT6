### Title
Unpermissioned `sign_btc_transaction` Allows Any Caller to Inject a Wrong `key_version`, Permanently Blocking Withdrawal Signing - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

### Summary
`sign_btc_transaction` carries no caller-identity restriction. Any NEAR account can invoke it for any pending withdrawal, supplying an arbitrary `key_version`. The MPC service will produce a signature under the wrong key, which is unconditionally stored in the pending-info slot. Because the slot is then non-`None`, the legitimate re-sign is blocked forever, leaving the user's nBTC locked in the bridge until an operator manually cancels the withdrawal.

### Finding Description
`sign_btc_transaction` is decorated only with `#[pause(except(roles(Role::DAO)))]` — a liveness guard, not an identity guard. [1](#0-0) 

No `#[access_control_any]`, no `require!(env::predecessor_account_id() == btc_pending_info.account_id, ...)`, and no whitelist check restricts who may call it. The three caller-controlled inputs are `btc_pending_sign_id` (selects the victim withdrawal), `sign_index` (selects the input slot), and `key_version` (selects the MPC key used to sign).

Inside `internal_sign_btc_transaction`, the `key_version` is forwarded verbatim to the MPC service: [2](#0-1) 

The callback then stores whatever signature the MPC service returns, guarded only by an `is_none()` check: [3](#0-2) 

Once `signatures[sign_index]` is `Some(...)`, the slot is permanently occupied. The legitimate owner cannot re-sign that input because the guard fires: [4](#0-3) 

The deposit address for each UTXO is derived from a specific key version (the one in use when the UTXO was registered). A signature produced under a different `key_version` will not satisfy the UTXO's `script_pubkey`, making the assembled Bitcoin transaction invalid and unbroadcastable.

### Impact Explanation
The user's nBTC is transferred to the bridge at withdrawal initiation (`ft_on_transfer`). If the signing slot is poisoned with a wrong-key-version signature, the withdrawal transaction can never be broadcast. The user's nBTC remains locked in the bridge. Recovery requires a DAO/Operator to call `cancel_withdraw`, which is an operator-intervention event and may not happen promptly. This matches the allowed impact: **attacker-triggered temporary locking of bridged funds requiring operator intervention (Medium)**. [5](#0-4) 

### Likelihood Explanation
Any NEAR account can watch on-chain events for `GenerateBtcPendingInfo` (emitted immediately when a withdrawal is created) and race to call `sign_btc_transaction` before the legitimate relayer does. The attack costs only the NEAR gas for one function call. No special privilege, leaked key, or majority attack is required. [6](#0-5) 

### Recommendation
Restrict `sign_btc_transaction` to the withdrawal owner or to a whitelisted relayer set, mirroring the pattern used on every other sensitive mutating endpoint in the contract:

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
    // Add: only the withdrawal owner or a trusted relayer may sign
    require!(
        env::predecessor_account_id() == btc_pending_info.account_id
            || self.is_trusted_relayer(&env::predecessor_account_id()),
        "Unauthorized"
    );
    ...
}
```

Additionally, validate that `key_version` matches the version recorded in the contract configuration to prevent signature-slot poisoning even if the caller restriction is bypassed.

### Proof of Concept

1. Alice calls `ft_transfer_call` on the nBTC contract, initiating a withdrawal. The bridge emits `GenerateBtcPendingInfo { btc_pending_id: "psbt_abc..." }`.
2. Attacker Bob observes the event and immediately calls:
   ```
   sign_btc_transaction(
       btc_pending_sign_id = "psbt_abc...",
       sign_index = 0,
       key_version = 999   // wrong version
   )
   ```
3. The bridge forwards the request to the MPC service with `key_version = 999`. The MPC service returns a valid ECDSA signature, but one produced under a key that does not correspond to Alice's deposit UTXO.
4. `sign_btc_transaction_callback` stores the signature: `btc_pending_info.signatures[0] = Some(bad_sig)`.
5. The legitimate relayer attempts `sign_btc_transaction(..., key_version = 0)`. The call hits `require!(btc_pending_info.signatures[0].is_none(), "Already signed")` and panics.
6. The assembled Bitcoin transaction (with `bad_sig` in input 0) is invalid; it cannot be broadcast. Alice's nBTC is permanently locked until a DAO/Operator calls `cancel_withdraw`. [7](#0-6)

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
