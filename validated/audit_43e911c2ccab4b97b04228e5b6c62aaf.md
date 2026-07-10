### Title
Permissionless `sign_btc_transaction` Allows Any Caller to Trigger MPC Signing for Any Pending Transaction - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

### Summary
The `sign_btc_transaction` function in `contracts/satoshi-bridge/src/api/chain_signatures.rs` contains no check that the caller is the owner of the referenced pending transaction. Any unprivileged NEAR account can invoke it for any `btc_pending_sign_id` with attacker-chosen `sign_index` and `key_version`, triggering an MPC signing request against a victim's pending withdrawal or refund PSBT without the owner's authorization. This is a direct structural analog to H-03: just as anyone could call `carryVoteForward()` for any `veKITTEN` NFT, anyone can call `sign_btc_transaction()` for any pending BTC transaction.

### Finding Description
`BTCPendingInfo` carries an `account_id` field that records the owner of each pending transaction. The `sign_btc_transaction` entry point retrieves the pending info but never compares `env::predecessor_account_id()` against `btc_pending_info.account_id`:

```rust
// contracts/satoshi-bridge/src/api/chain_signatures.rs  lines 21-43
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();
    // ← NO caller == btc_pending_info.account_id check
    ...
    self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
        .into()
}
```

Both `sign_index` and `key_version` are fully attacker-controlled. The function is `#[payable]` with no `assert_one_yocto()` guard and no role restriction beyond the global pause flag, so it is reachable by any NEAR account at zero cost.

**Exploit path:**

1. Alice initiates a withdrawal via `ft_transfer_call` → `ft_on_transfer` → `internal_sign_btc_transaction`, creating a `BTCPendingInfo` with `account_id = alice.near` and `btc_pending_sign_id = <psbt_hash>`.
2. Attacker observes the emitted `GenerateBtcPendingInfo` event (public on-chain log) to learn `btc_pending_sign_id`.
3. Attacker calls `sign_btc_transaction(<alice_pending_id>, 0, <wrong_key_version>)`.
4. The bridge dispatches an MPC `sign` cross-contract call with the attacker-chosen `key_version`. The MPC signs the PSBT payload with the key derived under the wrong version, producing a signature that does not correspond to the public key committed in Alice's PSBT.
5. `sign_btc_transaction_callback` stores the returned (invalid) signature in Alice's `BTCPendingInfo.signatures[0]` and marks that input as signed.
6. Alice's pending transaction now holds an invalid signature. The transaction cannot be broadcast to Bitcoin; it will be rejected by every node. Alice's deposit UTXO is locked inside the bridge with no valid spending path until an operator manually intervenes to reconstruct the pending state.

Even when called with the correct `key_version`, the attacker can supply a wrong `sign_index` (e.g., an out-of-range index), causing the callback to write a signature at an unexpected slot or panic mid-callback, leaving the pending info in a partially-signed, unrecoverable state.

### Impact Explanation
The direct consequence is a stuck bridge state: the victim's pending BTC transaction is corrupted and cannot be finalized or broadcast. The underlying UTXO remains locked in the bridge's MPC-controlled address. Recovery requires privileged operator intervention (e.g., manual state repair or a contract upgrade). No direct theft of funds occurs, but the victim's bridged assets are temporarily frozen and the bridge's UTXO set is left in an inconsistent state.

**Impact: Medium** — stuck bridge state requiring operator intervention, matching the allowed impact category "Bypass of bridge limits or policies, or attacker-triggered temporary locking of bridged funds."

### Likelihood Explanation
The function is publicly callable with no preconditions. The `btc_pending_sign_id` is derived from the PSBT hash and is emitted as a public on-chain event (`GenerateBtcPendingInfo`), so any observer can enumerate all active pending transactions. No privileged access, leaked key, or social engineering is required. Any NEAR account can execute this attack at any time against any pending withdrawal or refund.

**Likelihood: High.**

### Recommendation
Add an ownership check at the top of `sign_btc_transaction`, mirroring the pattern used elsewhere in the contract:

```rust
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();

    // ADD: enforce caller is the owner of this pending transaction
    require!(
        env::predecessor_account_id() == btc_pending_info.account_id,
        "Only the owner of the pending transaction can sign it"
    );
    ...
}
```

Alternatively, if permissionless signing is intentional (e.g., to allow relayers to advance stuck transactions), restrict the allowed `key_version` to the single value recorded at PSBT construction time and validate `sign_index` against the number of inputs in the stored PSBT before dispatching the MPC call.

### Proof of Concept

```
1. Alice calls ft_transfer_call(bridge, 100000, withdrawal_msg)
   → bridge emits: GenerateBtcPendingInfo { account_id: "alice.near", btc_pending_id: "aabbcc..." }

2. Attacker reads the event log and obtains btc_pending_id = "aabbcc..."

3. Attacker calls (no attached deposit required):
   sign_btc_transaction(
       btc_pending_sign_id = "aabbcc...",
       sign_index          = 0,
       key_version         = 9999          // wrong key version
   )

4. Bridge dispatches MPC sign({ payload: <psbt_sighash>, path: <alice_path>, key_version: 9999 })
   MPC returns signature S' (signed under key version 9999, not the key committed in Alice's PSBT)

5. sign_btc_transaction_callback stores S' in alice's BTCPendingInfo.signatures[0]
   and marks input 0 as signed.

6. Alice's pending transaction now contains an invalid signature.
   - Alice cannot re-sign (input already marked signed).
   - The transaction is rejected by Bitcoin nodes on broadcast.
   - Alice's UTXO is locked until operator intervention.
``` [1](#0-0) [2](#0-1)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L344-375)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
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
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```
