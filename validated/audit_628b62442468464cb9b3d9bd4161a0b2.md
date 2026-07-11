### Title
Unauthorized MPC Signing Trigger — Any Account Can Call `sign_btc_transaction` Without Ownership Check - (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

`sign_btc_transaction` imposes no check that the caller owns or is authorized to sign the referenced pending transaction. Any unprivileged NEAR account can supply an arbitrary `btc_pending_sign_id` and trigger the MPC signing pipeline for a withdrawal that belongs to a different user, bypassing the intended authorization gate on the signing step.

---

### Finding Description

The public entry point `sign_btc_transaction` is decorated only with `#[payable]` and `#[pause]`: [1](#0-0) 

After fetching the pending info and asserting it is in `PendingSign` state, the function immediately delegates to `internal_sign_btc_transaction` with no comparison between `env::predecessor_account_id()` and `btc_pending_info.account_id`: [2](#0-1) 

`internal_sign_btc_transaction` then calls the MPC service and, on success, stores the returned signature into the pending info's `signatures` slot and — once all inputs are signed — transitions the record to `PendingVerify` stage: [3](#0-2) 

The `btc_pending_sign_id` values are publicly observable: they are emitted in the `GenerateBtcPendingInfo` event at withdrawal creation time: [4](#0-3) 

The analog to the OTP-bypass report is exact: just as the original vulnerability let an attacker skip the OTP step and directly call `/transfer/create`, here an attacker can skip the ownership gate and directly call `sign_btc_transaction` on any pending withdrawal.

---

### Impact Explanation

Once all inputs of a pending withdrawal are signed (state transitions to `PendingVerify`), the user-facing `withdraw_rbf` path — which requires the transaction to still be in `PendingSign` state — is no longer available: [5](#0-4) 

An attacker who races to sign all inputs of a victim's pending withdrawal before the victim can call `withdraw_rbf` permanently removes the victim's ability to bump the fee or redirect the transaction to a different output set. The funds are not stolen (the PSBT outputs are fixed at withdrawal creation), but the victim's transaction is locked into its original fee/output configuration and cannot be adjusted, which can result in the withdrawal being stuck if the original fee is too low for current mempool conditions.

**Impact category**: Medium — attacker-triggered temporary/permanent locking of bridged funds in transit; bypass of a bridge policy (user-controlled RBF window).

---

### Likelihood Explanation

- `btc_pending_sign_id` values are emitted as on-chain events and are trivially observable by any NEAR indexer.
- The attacker needs only a small NEAR gas deposit (`#[payable]` with no `assert_one_yocto`).
- No privileged role, leaked key, or off-chain coordination is required.
- The race window exists for every withdrawal from the moment `ft_on_transfer` completes until the relayer signs.

**Likelihood**: Medium-High.

---

### Recommendation

Add an ownership or role check at the top of `sign_btc_transaction`. The simplest fix is to require that the caller is either the transaction owner or a whitelisted relayer:

```rust
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();

    // ADD: caller must be the owner or a trusted relayer
    let caller = env::predecessor_account_id();
    require!(
        caller == btc_pending_info.account_id
            || self.data().relayer_white_list.contains(&caller)
            || self.acl_has_any_role(vec![Role::DAO.into(), Role::UnrestrictedRelayer.into()], caller),
        "Unauthorized: caller is not the transaction owner or a trusted relayer"
    );
    ...
}
```

Alternatively, apply the existing `#[trusted_relayer]` macro to this method, consistent with how `verify_deposit` and `verify_withdraw` are protected.

---

### Proof of Concept

1. Alice calls `ft_transfer_call` on the nBTC contract with a `Withdraw` message. The bridge creates a `BTCPendingInfo` with `state = PendingSign` and emits `GenerateBtcPendingInfo { btc_pending_id: "abc123..." }`.
2. Alice decides the fee is too low and wants to call `withdraw_rbf` before the relayer signs.
3. Attacker Bob observes the `GenerateBtcPendingInfo` event on-chain and immediately calls:
   ```
   sign_btc_transaction(btc_pending_sign_id="abc123...", sign_index=0, key_version=0)
   ```
   with a small NEAR deposit. No ownership check fires.
4. The MPC service signs the transaction. The callback stores the signature and, since there is only one input, transitions the record to `PendingVerify`.
5. Alice's subsequent `withdraw_rbf` call panics because `assert_pending_sign()` fails — the record is no longer in `PendingSign` state.
6. Alice's withdrawal is now locked at the original (potentially too-low) fee, and she has no recourse until the operator calls `cancel_withdraw` on her behalf.

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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L135-140)
```rust
        Event::GenerateBtcPendingInfo {
            account_id: &sender_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
```
