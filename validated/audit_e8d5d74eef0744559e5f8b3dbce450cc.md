### Title
Front-Running `sign_btc_transaction` with Wrong `key_version` Permanently Invalidates Withdrawal Signing Slot - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

### Summary

`sign_btc_transaction` is publicly callable by any NEAR account with no authorization check on the caller. An attacker can front-run a legitimate relayer's signing call by submitting the same `btc_pending_sign_id` and `sign_index` with a wrong `key_version`. The MPC returns a signature for the wrong key, which is stored unconditionally in `signatures[sign_index]`. Because the slot is write-once (guarded by `"Already signed"`), the legitimate relayer's subsequent call is permanently blocked for that input, leaving the withdrawal PSBT with an invalid signature and the user's funds stuck.

### Finding Description

`sign_btc_transaction` carries only a `#[pause]` guard; there is no check that `env::predecessor_account_id()` is the owner of the pending transaction or any whitelisted relayer:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> {
``` [1](#0-0) 

Inside `internal_sign_btc_transaction`, the only pre-flight guard is:

```rust
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
``` [2](#0-1) 

The MPC is then called with the caller-supplied `key_version`:

```rust
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,
})
``` [3](#0-2) 

In the callback, the returned signature is stored **without verifying it against the expected public key** for the UTXO path:

```rust
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
btc_pending_info.signatures[sign_index] = Some(signature.clone());
``` [4](#0-3) 

Once the slot is filled, no further call to `sign_btc_transaction` for the same `(btc_pending_sign_id, sign_index)` pair can succeed. The `GenerateBtcPendingInfo` event emitted at withdrawal creation makes `btc_pending_sign_id` publicly observable:

```rust
Event::GenerateBtcPendingInfo {
    account_id: &sender_id,
    btc_pending_id: &btc_pending_id,
}
.emit();
``` [5](#0-4) 

### Impact Explanation

An attacker who front-runs the relayer with a wrong `key_version` causes the MPC to produce a signature for a different key version than the one that corresponds to the UTXO's derived path. That invalid signature is stored and the slot is permanently closed. The resulting "fully signed" PSBT carries a signature that does not satisfy the Bitcoin script, so the broadcast transaction is rejected by the Bitcoin network. The user's withdrawal is stuck in `PendingVerify` state until `max_btc_tx_pending_sec` elapses and an operator cancels the stale pending info. This constitutes attacker-triggered temporary locking of bridged funds.

### Likelihood Explanation

The attack requires only a standard NEAR account and enough attached deposit to cover the MPC signing fee. The `btc_pending_sign_id` is emitted on-chain in a public event immediately when a withdrawal is initiated, giving the attacker the exact identifier needed. The attacker simply submits `sign_btc_transaction` with `key_version = 1` (or any value other than the correct one) before the relayer does. On NEAR, transaction ordering within a block is deterministic and observable, making targeted front-running straightforward for a monitoring attacker.

### Recommendation

Add an authorization check so that only whitelisted relayers (or the account that owns the pending transaction) can call `sign_btc_transaction`. For example, gate the call behind `Role::UnrestrictedRelayer` or verify `env::predecessor_account_id() == btc_pending_info.account_id`. Additionally, validate the returned MPC signature against the expected public key derived from the UTXO path inside `sign_btc_transaction_callback` before storing it, so that a signature produced for the wrong key version is rejected rather than persisted.

### Proof of Concept

1. Alice calls `ft_transfer_call` on the nBTC contract to initiate a withdrawal. The bridge emits `GenerateBtcPendingInfo { btc_pending_id: "abc123", ... }`.
2. Attacker observes the event and immediately calls:
   ```
   sign_btc_transaction("abc123", 0, 999)  // wrong key_version
   ```
   with sufficient attached deposit.
3. MPC signs the payload with key version 999 (a different key than the UTXO's derived key). The callback stores the invalid signature: `signatures[0] = Some(bad_sig)`.
4. The legitimate relayer calls `sign_btc_transaction("abc123", 0, 0)`. The check `signatures[0].is_none()` fails → `"Already signed"` panic.
5. The PSBT is finalized with the invalid signature and emitted as `SignedBtcTransaction`. When broadcast to Bitcoin, the transaction is rejected.
6. Alice's withdrawal is stuck until `max_btc_tx_pending_sec` expires and an operator clears the stale pending info.

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-27)
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
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L91-94)
```rust
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L135-139)
```rust
        Event::GenerateBtcPendingInfo {
            account_id: &sender_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
```
