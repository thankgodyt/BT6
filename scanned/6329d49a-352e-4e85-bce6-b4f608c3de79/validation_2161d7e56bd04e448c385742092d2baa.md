### Title
Incorrect Recovery ID Encoding in `SignatureResponse::to_bytes()` Produces Signatures Incompatible with Solana's `secp256k1_recover` - (File: `near/omni-types/src/mpc_types.rs`)

### Summary

`SignatureResponse::to_bytes()` unconditionally adds 27 to the raw MPC `recovery_id` (producing v=27 or v=28, the Ethereum legacy convention). The Solana bridge program's `verify_signature` passes `self.signature[64]` directly to Solana's `secp256k1_recover` syscall, which only accepts recovery_id values of 0 or 1. If the NEAR bridge emits events containing signatures serialized via `to_bytes()`, every `finalize_transfer` and `deploy_token` call on Solana will fail with `SignatureVerificationFailed`, permanently stranding funds for any user who initiated a NEAR→Solana transfer.

### Finding Description

In `near/omni-types/src/mpc_types.rs`, `SignatureResponse::to_bytes()` serializes the MPC signature as `[r(32) || s(32) || (recovery_id + 27)(1)]`:

```rust
// near/omni-types/src/mpc_types.rs, line 49
bytes.push(self.recovery_id + 27);
```

The MPC service returns `recovery_id` as 0 or 1 (the raw parity bit). Adding 27 converts it to the Ethereum legacy `v` encoding (27 or 28). This is correct for EVM chains, where OpenZeppelin's `ECDSA.recover` expects v=27 or v=28.

However, the Solana bridge program's `verify_signature` in `solana/programs/bridge_token_factory/src/state/message/mod.rs` reads the last byte of the 65-byte signature and passes it directly to Solana's `secp256k1_recover`:

```rust
// solana/programs/bridge_token_factory/src/state/message/mod.rs, line 38
let signer = secp256k1_recover(&hash.to_bytes(), self.signature[64], signature_bytes)
    .map_err(|_| error!(ErrorCode::SignatureVerificationFailed))?;
```

Solana's `secp256k1_recover` syscall only accepts recovery_id values of 0 or 1. Passing 27 or 28 returns `Secp256k1RecoverError::InvalidRecoveryId`, which the program maps to `ErrorCode::SignatureVerificationFailed`.

The Solana unit-test helper `sign_payload` in `solana/programs/bridge_token_factory/tests/mollusk/helpers.rs` correctly uses `recid.serialize()` (which returns 0 or 1), confirming the Solana program's expected format — and revealing the mismatch with `to_bytes()`.

### Impact Explanation

Any user who initiates a NEAR→Solana transfer causes their tokens to be burned/locked on NEAR. The NEAR bridge then calls MPC, receives a `SignatureResponse`, serializes it via `to_bytes()` (producing v=27/28), and emits an event. A relayer picks up the event and calls `finalize_transfer` on Solana with the signature bytes. Because `self.signature[64]` is 27 or 28, `secp256k1_recover` returns `InvalidRecoveryId`, the instruction reverts with `SignatureVerificationFailed`, and the user's tokens are permanently stranded — burned on NEAR, never minted/unlocked on Solana. The same applies to `deploy_token` calls on Solana.

### Likelihood Explanation

Every NEAR→Solana transfer goes through this code path. The bug is systemic: it affects 100% of Solana-bound transfers if `to_bytes()` is used in the event emission path (confirmed by grep matches in `near/omni-types/src/near_events.rs`). No special attacker action is required; any ordinary bridge user triggers it.

### Recommendation

In `SignatureResponse::to_bytes()`, do not add 27 to `recovery_id` unconditionally. Either:
- Keep the raw parity bit (0 or 1) in the serialized bytes and update EVM consumers to add 27 themselves, or
- Provide two serialization methods: one for EVM (adds 27) and one for Solana/raw (no offset).

The Solana `verify_signature` should document that it expects recovery_id 0 or 1, and the NEAR event emission for Solana-bound signatures must use the raw parity bit.

### Proof of Concept

1. User initiates a NEAR→Solana transfer; tokens are burned on NEAR.
2. NEAR bridge calls MPC; MPC returns `SignatureResponse { recovery_id: 0, ... }`.
3. `to_bytes()` serializes the signature with byte 64 = `0 + 27 = 27`.
4. Relayer submits `finalize_transfer` to Solana with this 65-byte signature.
5. `verify_signature` calls `secp256k1_recover(..., 27, ...)`.
6. Solana syscall returns `Secp256k1RecoverError::InvalidRecoveryId`.
7. Instruction reverts with `SignatureVerificationFailed`.
8. User's tokens are permanently lost.

---

**Root cause locations:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** near/omni-types/src/mpc_types.rs (L43-52)
```rust
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &hex::decode(&self.big_r.affine_point).expect("Incorrect Signature")[1..],
        );
        bytes.extend_from_slice(&hex::decode(&self.s.scalar).expect("Incorrect Signature"));
        bytes.push(self.recovery_id + 27);

        bytes
    }
```

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L38-39)
```rust
        let signer = secp256k1_recover(&hash.to_bytes(), self.signature[64], signature_bytes)
            .map_err(|_| error!(ErrorCode::SignatureVerificationFailed))?;
```

**File:** solana/programs/bridge_token_factory/tests/mollusk/helpers.rs (L431-442)
```rust
/// Sign serialized payload: keccak256 hash then secp256k1 sign.
/// Returns [r(32) || s(32) || recovery_id(1)] = 65 bytes.
pub fn sign_payload(secret: &libsecp256k1::SecretKey, data: &[u8]) -> [u8; 65] {
    let hash: [u8; 32] = Keccak256::digest(data).into();
    let message = libsecp256k1::Message::parse(&hash);
    let (sig, recid) = libsecp256k1::sign(&message, secret);

    let mut result = [0u8; 65];
    result[..64].copy_from_slice(&sig.serialize());
    result[64] = recid.serialize();
    result
}
```
