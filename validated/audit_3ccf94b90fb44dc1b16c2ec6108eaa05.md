### Title
Any NEAR Account Can Call `sign_btc_transaction` With Arbitrary `key_version`, Potentially Corrupting Pending Withdrawal Signatures and Locking User Funds - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

### Summary

The `sign_btc_transaction` function in the satoshi-bridge contract has **no access control** — any NEAR account can call it. Combined with an unvalidated `key_version` parameter that is passed directly to the MPC chain-signatures service, an attacker can front-run the legitimate relayer, cause the MPC to sign with the wrong key, and have that invalid signature saved into the pending withdrawal info. Once a signature slot is filled, it cannot be overwritten, leaving the withdrawal permanently stuck in the sign stage.

### Finding Description

`sign_btc_transaction` is decorated only with `#[payable]` and `#[pause(except(roles(Role::DAO)))]` — no role check, no `#[trusted_relayer]`, no `#[access_control_any]`:

```rust
// contracts/satoshi-bridge/src/api/chain_signatures.rs
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,          // ← caller-controlled, never validated
) -> PromiseOrValue<bool> {
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
    btc_pending_info.assert_pending_sign();
    ...
    self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
        .into()
}
```

`internal_sign_btc_transaction` passes `key_version` verbatim to the MPC:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs
self.sign_promise(SignRequest {
    payload,
    path,
    key_version,   // ← no validation, any u32 accepted
})
```

The callback saves whatever signature the MPC returns, then checks the slot is empty — but does **not** verify the signature against the expected public key before persisting it:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs
require!(
    btc_pending_info.signatures[sign_index].is_none(),
    "Already signed"
);
btc_pending_info.signatures[sign_index] = Some(signature.clone());
...
psbt.save_signature(sign_index, signature, public_key);
```

Once a slot is filled, the legitimate relayer's subsequent call panics with `"Already signed"`. The PSBT is then finalized with the wrong-key signature, the transaction is broadcast to Bitcoin, and Bitcoin rejects it as invalid. The withdrawal is stuck.

The analog to M-10 is direct: in M-10, `onlyAcceptedCallers` was too broad (liquidators could call a loan-contract-only function). Here, the guard is entirely absent — any NEAR account substitutes for the trusted relayer, bypassing the implicit assumption that only a correctly-configured relayer would supply the right `key_version`.

### Impact Explanation

If the MPC chain-signatures service accepts a `key_version` value that does not correspond to the key committed in the PSBT's input scripts, the resulting signature is cryptographically valid for the wrong key. Bitcoin will reject the transaction. The bridge has no mechanism to re-sign an already-signed slot; the only recovery path is DAO/Operator-initiated `cancel_withdraw` (a privileged operation), meaning the user's nBTC remains locked in the bridge balance until operator intervention. This matches the **Medium** impact category: *attacker-triggered temporary locking of bridged funds*.

### Likelihood Explanation

- The `btc_pending_sign_id` is emitted publicly via `Event::GenerateBtcPendingInfo` immediately after a withdrawal is initiated, so any on-chain observer can learn it.
- The attacker must front-run the legitimate relayer's `sign_btc_transaction` call, which is feasible given NEAR's public mempool and the fact that relayers typically sign within a predictable window.
- The attacker must attach enough NEAR to cover the MPC signing deposit — a small economic cost.
- The attack succeeds only if the MPC accepts the supplied `key_version`; if the MPC rejects unknown versions the callback returns `false` harmlessly. However, the bridge code imposes no such guard itself, making the exposure entirely dependent on MPC configuration rather than on-chain enforcement.

### Recommendation

1. **Restrict callers**: Add `#[trusted_relayer]` (or `#[access_control_any(roles(Role::DAO, Role::Operator, Role::UnrestrictedRelayer))]`) to `sign_btc_transaction` so only whitelisted relayers or privileged roles can invoke it.
2. **Validate `key_version`**: Store the expected `key_version` in `Config` and assert `key_version == config.expected_key_version` before forwarding to the MPC.
3. **Verify signature before saving**: In `sign_btc_transaction_callback`, verify the returned signature against the expected public key (derived from the UTXO path) before persisting it to `btc_pending_info.signatures`.

### Proof of Concept

1. Alice initiates a withdrawal via `nbtc.ft_transfer_call(bridge, amount, WithdrawMsg)`.
2. The bridge emits `GenerateBtcPendingInfo { btc_pending_id: "abc123" }`.
3. Attacker observes the event and immediately calls:
   ```
   bridge.sign_btc_transaction(
       btc_pending_sign_id = "abc123",
       sign_index = 0,
       key_version = 1,          // wrong key version
       attached_deposit = <MPC fee>
   )
   ```
4. MPC signs the payload with key version 1 (a different key than the one committed in the PSBT).
5. `sign_btc_transaction_callback` saves the wrong-key signature; slot 0 is now `Some(...)`.
6. Legitimate relayer calls `sign_btc_transaction("abc123", 0, 0)` → panics `"Already signed"`.
7. Bridge finalizes the PSBT with the invalid signature and emits `SignedBtcTransaction`.
8. Relayer broadcasts the transaction; Bitcoin rejects it (bad signature).
9. `verify_withdraw` can never succeed; Alice's nBTC remains locked in the bridge until a DAO/Operator calls `cancel_withdraw`.