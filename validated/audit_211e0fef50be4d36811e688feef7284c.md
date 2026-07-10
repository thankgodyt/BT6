### Title
O(n) KDF Derivation Loop Per Signing Call in `internal_sign_btc_transaction` May Cause Gas Exhaustion and Permanent Fund Lock - (File: contracts/satoshi-bridge/src/chain_signature.rs)

### Summary
Every call to `sign_btc_transaction` (one per PSBT input) unconditionally derives public keys for **all** inputs via `generate_btc_public_key`, an expensive KDF/elliptic-curve operation. With `max_withdrawal_input_number` configurable up to 255 (a `u8`), a user can craft a withdrawal with the maximum number of inputs, making each signing call O(n) in KDF operations. If the cumulative gas cost of n KDF operations plus the cross-contract sign overhead exceeds NEAR's hard 300 Tgas per-transaction ceiling, the signing call can never succeed regardless of attached gas, permanently locking the user's nBTC tokens and the bridge's UTXOs.

### Finding Description

In `internal_sign_btc_transaction`, before issuing the MPC sign request for a single input at `sign_index`, the function iterates over **every** vutxo to derive its public key: [1](#0-0) 

```rust
let public_keys: Vec<_> = pending_info
    .vutxos
    .iter()
    .map(|vutxo| self.generate_btc_public_key(&vutxo.get_path()))
    .collect();
```

This O(n) derivation happens on **every** call to `sign_btc_transaction`, even though only one input (`sign_index`) is being signed. Because `sign_btc_transaction` must be called once per input, the total KDF work across the full signing lifecycle is O(n²).

The callback, by contrast, derives only the single key it needs: [2](#0-1) 

```rust
let public_key = self
    .generate_btc_public_key(
        &self
            .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
            .vutxos[sign_index]
            .get_path(),
    )
    .inner;
```

This asymmetry confirms the full-iteration in the main function is not required for correctness. For P2WPKH/SegWit v0, the sighash for input `i` requires only the scriptCode derived from input `i`'s public key; the public keys of other inputs are not part of the BIP-143 sighash preimage.

The gas budget available to the pre-call logic is constrained by the fixed allocations: [3](#0-2) 

```rust
pub const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(50);
pub const GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK: Gas = Gas::from_tgas(30);
```

These 80 Tgas are reserved for the cross-contract call chain, leaving at most ~220 Tgas for the pre-call logic. If n KDF derivations consume more than ~220 Tgas, the transaction panics before the MPC sign call is ever issued.

The number of inputs is bounded by `max_withdrawal_input_number`, a `u8` field: [4](#0-3) 

The limit check is enforced only inside `check_withdraw_psbt_valid`, which runs **after** `generate_vutxos` has already removed UTXOs from the pool: [5](#0-4) 

Once the `BTCPendingInfo` is created with n inputs, the UTXOs are gone from the pool and the nBTC tokens are held by the bridge. If signing can never complete, both are permanently inaccessible.

### Impact Explanation

If `max_withdrawal_input_number` is set to a value where n KDF operations exceed ~220 Tgas, every call to `sign_btc_transaction` for that pending info will panic. NEAR's 300 Tgas hard ceiling cannot be raised by the caller. The result is:

- The user's nBTC tokens (already transferred to the bridge in `ft_on_transfer`) are permanently locked.
- The bridge's UTXOs (already removed from the pool in `generate_vutxos`) are permanently locked in the pending info and unavailable for other withdrawals.

This matches: **Medium — attacker-triggered temporary (potentially permanent) locking of bridged funds.**

### Likelihood Explanation

Any nBTC holder can trigger this by initiating a withdrawal (`ft_on_transfer` → `TokenReceiverMessage::Withdraw`) with the maximum allowed number of inputs. No privileged role is required. The attacker only needs to hold nBTC (obtainable by depositing BTC through the normal deposit flow). The severity of the gas exhaustion scales with the configured `max_withdrawal_input_number` and the actual per-call cost of `generate_btc_public_key`.

### Recommendation

Replace the full-vutxo iteration with a targeted single-key derivation for `sign_index` only:

```rust
// Before: derives all n keys on every call
let public_keys: Vec<_> = pending_info
    .vutxos
    .iter()
    .map(|vutxo| self.generate_btc_public_key(&vutxo.get_path()))
    .collect();

// After: derive only the key needed for this sign_index
let signing_key = self.generate_btc_public_key(
    &pending_info.vutxos[sign_index].get_path()
);
```

If `get_hash_to_sign` genuinely requires all public keys for the sighash preimage, cache the derived public keys inside `BTCPendingInfo` at pending-info creation time (when the PSBT is first validated), so each signing call performs O(1) KDF work.

### Proof of Concept

1. Attacker deposits BTC to receive nBTC tokens.
2. Attacker calls `ft_transfer_call` on the nBTC contract targeting the bridge with `TokenReceiverMessage::Withdraw` containing `input: [utxo_1, utxo_2, ..., utxo_N]` where N = `max_withdrawal_input_number`.
3. Bridge removes all N UTXOs from the pool and creates a `BTCPendingInfo` with `signatures: vec![None; N]`.
4. Relayer calls `sign_btc_transaction(pending_id, 0, 0)`. The function derives N public keys via KDF before issuing the MPC sign call. If N × cost(KDF) > ~220 Tgas, the call panics.
5. Every subsequent attempt to sign any input of this pending info also panics for the same reason.
6. The N UTXOs and the attacker's nBTC tokens remain locked in the pending info indefinitely with no recovery path. [6](#0-5) [7](#0-6) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L7-8)
```rust
pub const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(50);
pub const GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK: Gas = Gas::from_tgas(30);
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L145-152)
```rust
            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
```

**File:** contracts/satoshi-bridge/src/config.rs (L89-89)
```rust
    pub max_withdrawal_input_number: u8,
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L71-140)
```rust
    pub(crate) fn create_btc_pending_info(
        &mut self,
        sender_id: AccountId,
        amount: u128,
        target_btc_address: String,
        mut psbt: PsbtWrapper,
        max_gas_fee: Option<U128>,
    ) {
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );

        let withdraw_change_address_script_pubkey =
            self.internal_config().get_change_script_pubkey();
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );

        let need_signature_num = psbt.get_input_num();
        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();
        let btc_pending_info = BTCPendingInfo {
            account_id: sender_id.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: amount,
            actual_received_amount,
            withdraw_fee,
            gas_fee,
            burn_amount: actual_received_amount + gas_fee,
            psbt_hex,
            vutxos,
            signatures: vec![None; need_signature_num],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::WithdrawOriginal(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
        Event::UtxoRemoved { utxo_storage_keys }.emit();
        Event::GenerateBtcPendingInfo {
            account_id: &sender_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
    }
```
