### Title
Missing `chain_id` in `MetadataPayload::to_borsh` Enables Cross-Chain Replay of `deploy_token` MPC Signatures — (`starknet/src/bridge_types.cairo`)

---

### Summary

`MetadataPayload::to_borsh` serializes the signed payload for `deploy_token` without including any chain identifier. In contrast, `TransferMessagePayload::to_borsh` correctly embeds `chain_id` twice. Because the same MPC-derived Ethereum address (`omni_bridge_derived_address`) is intended to be shared across all OmniBridge deployments, a valid `deploy_token` signature obtained for one Starknet instance can be replayed verbatim on any other Starknet instance that shares the same MPC key.

---

### Finding Description

`MetadataPayload::to_borsh` encodes only `[payload_type=1, token, name, symbol, decimals]`: [1](#0-0) 

No `chain_id` field is appended. Compare this with `TransferMessagePayload::to_borsh`, which explicitly embeds `chain_id` at two positions: [2](#0-1) 

`deploy_token` calls `payload.to_borsh()` with no chain argument and passes the result directly to `_verify_borsh_signature`: [3](#0-2) 

`_verify_borsh_signature` verifies the Keccak hash of those bytes against `omni_bridge_derived_address`: [4](#0-3) 

Because the Borsh bytes are identical regardless of which chain instance is targeted, any valid MPC signature for `deploy_token` on chain A is also a valid signature on chain B.

The only guard inside `deploy_token` that could block a replay is the idempotency check: [5](#0-4) 

This check operates on the per-contract `near_to_starknet_token` mapping, so it only prevents double-deployment within the same contract instance. It provides no cross-chain protection.

`fin_transfer`, by contrast, passes `self.omni_bridge_chain_id.read()` into `to_borsh`, correctly binding the signature to the target chain: [6](#0-5) 

---

### Impact Explanation

An attacker who observes a valid `(signature, MetadataPayload)` pair accepted on OmniBridge instance A can submit the identical pair to OmniBridge instance B. `_verify_borsh_signature` will accept it because the signed bytes are chain-agnostic. The token is then registered as a bridge token on instance B (`starknet_to_near_token` and `near_to_starknet_token` mappings are populated). Once registered, `fin_transfer` on instance B will treat it as a bridge token and call `mint` on it, enabling unauthorized minting of bridged assets on chain B for transfers the MPC never authorized for that chain.

---

### Likelihood Explanation

The precondition — the same `omni_bridge_derived_address` used across multiple Starknet deployments — is the intended design of the protocol (one MPC key governs all chains). Valid `deploy_token` signatures are observable on-chain as soon as any token is deployed on any instance. No privileged access, key compromise, or threshold collusion is required. The replay requires only submitting a public transaction.

---

### Recommendation

Add `chain_id` to `MetadataPayload::to_borsh`, mirroring the pattern already used in `TransferMessagePayload::to_borsh`:

```cairo
fn to_borsh(self: @MetadataPayload, chain_id: u8) -> ByteArray {
    let mut borsh_bytes: ByteArray = Default::default();
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append_byte(chain_id);          // <-- add this
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
    borsh_bytes
}
```

Update `deploy_token` to pass `self.omni_bridge_chain_id.read()` to `to_borsh`, and ensure the MPC signing service includes `chain_id` when producing `deploy_token` signatures.

---

### Proof of Concept

1. Deploy two OmniBridge instances, A (`omni_bridge_chain_id = 1`) and B (`omni_bridge_chain_id = 2`), both with the same `omni_bridge_derived_address`.
2. Call `deploy_token` on instance A with a valid MPC-signed `(signature, MetadataPayload)` for token `"near.token"`. The call succeeds.
3. Submit the identical `(signature, MetadataPayload)` to instance B's `deploy_token`. Because `MetadataPayload::to_borsh` produces the same bytes on both instances, `_verify_borsh_signature` accepts the signature and the call succeeds.
4. Token `"near.token"` is now registered as a bridge token on instance B.
5. Call `fin_transfer` on instance B with a crafted `TransferMessagePayload` targeting the newly deployed token. `fin_transfer` calls `mint` on it, minting tokens the MPC never authorized for chain B.

### Citations

**File:** starknet/src/bridge_types.cairo (L36-44)
```text
    fn to_borsh(self: @MetadataPayload) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::Metadata.into());
        borsh_bytes.append(@borsh::encode_byte_array(self.token));
        borsh_bytes.append(@borsh::encode_byte_array(self.name));
        borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
        borsh_bytes.append_byte(*self.decimals);
        borsh_bytes
    }
```

**File:** starknet/src/bridge_types.cairo (L61-71)
```text
    fn to_borsh(self: @TransferMessagePayload, chain_id: u8) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::TransferMessage.into());
        borsh_bytes.append(@borsh::encode_u64(*self.destination_nonce));
        borsh_bytes.append_byte(*self.origin_chain);
        borsh_bytes.append(@borsh::encode_u64(*self.origin_nonce));
        borsh_bytes.append_byte(chain_id);
        borsh_bytes.append(@borsh::encode_address(*self.token_address));
        borsh_bytes.append(@borsh::encode_u128(*self.amount));
        borsh_bytes.append_byte(chain_id);
        borsh_bytes.append(@borsh::encode_address(*self.recipient));
```

**File:** starknet/src/omni_bridge.cairo (L202-205)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
```

**File:** starknet/src/omni_bridge.cairo (L208-209)
```text
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');
```

**File:** starknet/src/omni_bridge.cairo (L252-254)
```text
            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );
```

**File:** starknet/src/omni_bridge.cairo (L398-406)
```text
    fn _verify_borsh_signature(
        ref self: ContractState, borsh_bytes: @ByteArray, signature: Signature,
    ) {
        let message_hash_le = compute_keccak_byte_array(borsh_bytes);
        let message_hash = reverse_u256_bytes(message_hash_le);

        let sig = signature_from_vrs(signature.v, signature.r, signature.s);
        verify_eth_signature(message_hash, sig, self.omni_bridge_derived_address.read());
    }
```
