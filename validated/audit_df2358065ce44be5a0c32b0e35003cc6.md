### Title
Hardcoded `key_version: 0` in `sign_transfer` causes permanent fund loss after MPC key rotation — (File: `near/omni-bridge/src/lib.rs`)

### Summary
`sign_transfer` hardcodes `key_version: 0` in every MPC `SignRequest`. If the NEAR MPC key is rotated (a normal operational procedure analogous to Wormhole guardian-set rotation in M-03), all in-flight pending transfers whose tokens are already burned/locked on NEAR become permanently irrecoverable, because the bridge has no mechanism to re-sign with the new key version and no cancel/refund path for the user.

### Finding Description
`sign_transfer` builds a `SignRequest` with `key_version: 0` hardcoded:

```rust
ext_signer::ext(self.mpc_signer.clone())
    .sign(SignRequest {
        payload,
        path: SIGN_PATH.to_owned(),
        key_version: 0,          // ← always 0
    })
```

The same hardcoding appears in `log_metadata_callback`.

When a user calls `ft_on_transfer` → `init_transfer_internal`, their NEP-141 tokens are **burned or locked** and the transfer is inserted into `pending_transfers`. From that point the only forward path is for a relayer to call `sign_transfer`, which requests an MPC signature, and then submit that signature to the destination-chain bridge contract (e.g. `OmniBridge.sol`), which verifies it against `nearBridgeDerivedAddress` — an Ethereum address derived from the MPC root public key at deployment time.

If the MPC key is rotated (key version 0 → 1), two failure modes arise:

**Mode A — MPC contract rejects the old key version:** The MPC signer contract returns an error for `key_version: 0`. `sign_transfer_callback` receives `Err(PromiseError)` and silently does nothing — the transfer stays in `pending_transfers`, tokens remain burned/locked, and there is no recovery path.

**Mode B — MPC contract still accepts the old key but the EVM bridge is updated:** The MPC contract produces a valid secp256k1 signature under the old key. The EVM bridge contract, after being upgraded to reflect the new `nearBridgeDerivedAddress` (derived from the new root public key), rejects the signature. The relayer cannot re-sign with `key_version: 1` because the NEAR bridge hardcodes `0`. The transfer is permanently stuck.

`sign_