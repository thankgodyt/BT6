### Title
Unrestricted `key_version` in `sign_btc_transaction` Allows Any Caller to Poison MPC Signature Slots and Permanently Lock User Withdrawals - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

---

### Summary

`sign_btc_transaction` is a public, permissionless function that accepts a caller-controlled `key_version` parameter with no validation. Any NEAR account can call it for any pending transaction. By frontrunning the legitimate signer with a wrong `key_version`, an attacker causes the MPC to produce a signature under a different key than the one controlling the UTXO. The callback stores this invalid signature and the "Already signed" guard permanently blocks re-signing, leaving the withdrawal transaction unbroadcastable and user nBTC stuck in the bridge.

---

### Finding Description

`sign_btc_transaction` in `contracts/satoshi-bridge/src/api/chain_signatures.rs` performs no check on `env::predecessor_account_id()` against `btc_pending_info.account_id`:

```rust
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,          // ← fully attacker-controlled
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();
    // ← no predecessor == account_id check
    self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
        .into()
}
``` [1](#0-0) 

`internal_sign_btc_transaction` forwards the attacker-supplied `key_version` verbatim to the MPC:

```rust
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← attacker value passed to MPC
})
``` [2](#0-1) 

The MPC signs with the key corresponding to `key_version`. A different `key_version` produces a signature under a different secp256k1 key — one that does not correspond to the Bitcoin address holding the UTXO.

The callback stores the result without any signature validity check and then enforces a one-shot guard:

```rust
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
btc_pending_info.signatures[sign_index] = Some(signature.clone());
``` [3](#0-2) 

Once the slot is filled with an invalid signature, no further signing is possible for that input index.

**Attack path:**

1. User calls `nbtc.ft_transfer_call` → nBTC tokens are transferred to the bridge; a `BTCPendingInfo` with `PendingInfoStage::PendingSign` is created. The `btc_pending_sign_id` is public on-chain state.
2. Attacker observes the new pending ID and calls `sign_btc_transaction(btc_pending_sign_id, 0, 999)` with a wrong `key_version` (e.g. 999).
3. MPC signs the correct PSBT hash but with key version 999 — a key that does not control the UTXO.
4. `sign_btc_transaction_callback` stores the invalid signature and marks the slot filled.
5. The legitimate call `sign_btc_transaction(btc_pending_sign_id, 0, 0)` panics with "Already signed".
6. The PSBT can never be completed; the signed transaction can never be broadcast to Bitcoin.
7. User's nBTC remains locked in the bridge balance indefinitely.

The same attack applies to refund transactions (state `PendingInfoState::Refund`) and active UTXO management transactions, since all share the same `sign_btc_transaction` entry point. [4](#0-3) 

---

### Impact Explanation

User nBTC tokens are transferred to the bridge at withdrawal initiation and remain there until `verify_withdraw` burns them. If the signing step is poisoned, the Bitcoin transaction is never broadcast, `verify_withdraw` is never called, and the tokens are stuck. Recovery requires a privileged `cancel_withdraw` call by DAO/Operator, which is a stuck bridge state requiring operator intervention. This matches the **Medium** impact category: attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention.

For refund transactions the impact is worse: the user's original BTC deposit is also unrecoverable until an operator intervenes, since the refund PSBT cannot be completed.

---

### Likelihood Explanation

The `btc_pending_sign_id` is observable on-chain via `get_btc_pending_infos_paged`. Any NEAR account can submit the attack transaction. NEAR transaction ordering within a block is deterministic and observable in the mempool, making frontrunning straightforward. No special privileges, tokens, or off-chain resources are required. The attacker only needs to pay NEAR gas.

---

### Recommendation

1. **Restrict the caller**: add a check that `env::predecessor_account_id() == btc_pending_info.account_id` (or allow a whitelisted relayer set) at the top of `sign_btc_transaction`.

2. **Validate `key_version`**: store the expected `key_version` in `BTCPendingInfo` at creation time (derived from the current MPC config) and assert it matches the caller-supplied value before forwarding to the MPC.

3. **Verify the returned signature**: in `sign_btc_transaction_callback`, verify the returned signature against the known public key for the UTXO path before storing it, so an invalid signature is rejected rather than stored.

---

### Proof of Concept

```
1. Alice calls nbtc.ft_transfer_call(bridge, 100000, withdraw_msg)
   → Bridge creates BTCPendingInfo { account_id: "alice", state: Refund/Withdraw(PendingSign), signatures: [None] }
   → btc_pending_sign_id = "abc123..." (visible via get_btc_pending_infos_paged)

2. Attacker calls bridge.sign_btc_transaction("abc123...", 0, key_version=999)
   → internal_sign_btc_transaction sends SignRequest { payload: <correct hash>, path: <correct path>, key_version: 999 }
   → MPC returns Signature(key_999) — valid ECDSA but for the wrong key

3. sign_btc_transaction_callback:
   require!(signatures[0].is_none())  → passes (slot was None)
   signatures[0] = Some(Signature(key_999))  → slot now filled with invalid sig

4. Alice calls bridge.sign_btc_transaction("abc123...", 0, key_version=0)
   → sign_btc_transaction_callback:
   require!(signatures[0].is_none())  → PANICS "Already signed"

5. Alice's withdrawal is permanently stuck. nBTC locked in bridge.
   Bitcoin UTXO unspendable. Operator must cancel_withdraw to recover nBTC.
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L99-103)
```rust
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L154-158)
```rust
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L69-77)
```rust
pub enum PendingInfoState {
    WithdrawOriginal(OriginalState),
    WithdrawUserRbf(RbfState),
    WithdrawCancelRbf(RbfState),
    ActiveUtxoManagementOriginal(OriginalState),
    ActiveUtxoManagementRbf(RbfState),
    ActiveUtxoManagementCancelRbf(RbfState),
    Refund(OriginalState),
}
```
