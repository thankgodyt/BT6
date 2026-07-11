### Title
Unrestricted `sign_btc_transaction` Allows Any Caller to Inject Attacker-Controlled `key_version` into MPC Signing, Causing Stuck Withdrawal State - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

### Summary
`sign_btc_transaction` carries no caller-identity restriction. Any unprivileged NEAR account can invoke it for any pending BTC transaction and supply an arbitrary `key_version`. If the MPC service accepts the wrong version and returns a signature, the signature slot is permanently sealed by the "Already signed" guard, preventing the legitimate relayer from ever re-signing with the correct key. The resulting transaction is cryptographically invalid on Bitcoin, locking the user's nBTC in the bridge until an operator manually cancels the withdrawal.

### Finding Description
The public entry point `sign_btc_transaction` is decorated only with `#[payable]` and `#[pause(except(roles(Role::DAO)))]`. There is no `#[trusted_relayer]`, no `#[access_control_any]`, and no runtime check that the caller owns or is authorized to advance the pending transaction. [1](#0-0) 

The caller-supplied `key_version` is forwarded verbatim to the MPC chain-signatures service: [2](#0-1) 

Inside `sign_btc_transaction_callback`, the returned signature is stored unconditionally (no cryptographic validation against the expected public key), and the "Already signed" guard immediately seals the slot: [3](#0-2) 

The public key retrieved in the callback is used only for PSBT serialization (`psbt.save_signature`), not to verify the MPC-returned signature before storage. A signature produced under a different `key_version` is therefore stored without rejection. [4](#0-3) 

Contrast this with every sensitive deposit/withdraw verification function, which carries `#[trusted_relayer]`: [5](#0-4) [6](#0-5) 

`sign_btc_transaction` is the only state-mutating function in the signing pipeline that lacks this guard.

### Impact Explanation
Once the attacker's call succeeds and a signature for the wrong `key_version` is stored, the legitimate relayer's subsequent call to `sign_btc_transaction` with the correct version is rejected with "Already signed". The PSBT is then finalized with an invalid signature via `extract_tx_bytes_with_sign`, and the resulting Bitcoin transaction is cryptographically invalid. It will never confirm on-chain, so `verify_withdraw` can never succeed, and the nBTC burn never executes. The user's nBTC remains locked in the bridge balance indefinitely. Recovery requires a privileged `cancel_withdraw` call by DAO/Operator, constituting a stuck bridge state requiring operator intervention. [7](#0-6) 

### Likelihood Explanation
The NEAR chain-signatures MPC service exposes a `key_version` field in its `sign` interface. If the service supports more than one live key version (e.g., version 0 and version 1 during a key rotation), an attacker can supply the alternate valid version. The attacker needs only: (a) knowledge of a valid alternate `key_version` (observable from MPC documentation or on-chain state), and (b) the `btc_pending_sign_id` of a victim's pending withdrawal (observable from contract view calls). No privileged access is required. The attack is a single NEAR transaction.

### Recommendation
Apply the same `#[trusted_relayer]` macro used on all other sensitive bridge entry points to `sign_btc_transaction`, restricting callers to whitelisted relayers or accounts holding `Role::UnrestrictedRelayer`. Alternatively, add an explicit runtime check that `env::predecessor_account_id()` matches `btc_pending_info.account_id` (the withdrawal owner). Additionally, validate the MPC-returned signature against the expected public key inside `sign_btc_transaction_callback` before storing it, so a signature produced under a wrong key is rejected rather than sealed into the slot.

### Proof of Concept
1. Alice initiates a withdrawal via `ft_transfer_call`; the bridge creates `BTCPendingInfo` with id `"abc123"` in `PendingSign` state.
2. Attacker observes `"abc123"` via `get_btc_pending_infos_paged` (public view call).
3. Attacker calls `sign_btc_transaction("abc123", 0, 1)` (alternate valid `key_version`).
4. MPC signs the payload under key version 1 and returns a `SignatureResponse`.
5. `sign_btc_transaction_callback` stores the signature: `signatures[0] = Some(sig_v1)`.
6. Legitimate relayer calls `sign_btc_transaction("abc123", 0, 0)` → panics: `"Already signed"`.
7. `is_all_signed()` becomes true; `extract_tx_bytes_with_sign()` produces a Bitcoin transaction signed with the wrong key — invalid on-chain.
8. `verify_withdraw` is never callable successfully; Alice's nBTC remains locked in the bridge.
9. DAO/Operator must call `cancel_withdraw` to unblock Alice, constituting operator-required intervention.

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L96-103)
```rust
            .get_psbt()
            .get_hash_to_sign(sign_index, &public_keys);
        let path = btc_pending_info.vutxos[sign_index].get_path();
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-73)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L240-242)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_withdraw_v2(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
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
