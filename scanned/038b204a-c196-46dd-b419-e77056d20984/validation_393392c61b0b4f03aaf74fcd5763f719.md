The code confirms the vulnerability is real. Here is the full analysis:

---

### Title
Missing Chain-ID in `MetadataPayload::to_borsh()` Enables Cross-Chain Replay of `deploy_token` MPC Signatures — (`starknet/src/bridge_types.cairo`)

### Summary

`MetadataPayload::to_borsh()` serializes the token deployment payload without any chain identifier. Because the same MPC-derived Ethereum address (`omni_bridge_derived_address`) is shared across all OmniBridge deployments, a valid `deploy_token` signature obtained for chain A is byte-for-byte valid on chain B, allowing an attacker to deploy tokens on unauthorized chains without a chain-specific MPC authorization.

### Finding Description

`TransferMessagePayload::to_borsh()` correctly binds its payload to a specific chain by embedding `chain_id` twice in the serialized bytes: [1](#0-0) 

`MetadataPayload::to_borsh()` encodes only `PayloadType::Metadata`, `token`, `name`, `symbol`, and `decimals` — **no chain identifier at any position**: [2](#0-1) 

`deploy_token` calls `to_borsh()` with no chain argument and passes the result directly to `_verify_borsh_signature`: [3](#0-2) 

`_verify_borsh_signature` verifies the keccak digest against `omni_bridge_derived_address`, which is the same MPC key address across all deployments: [4](#0-3) 

By contrast, `fin_transfer` correctly passes `self.omni_bridge_chain_id.read()` into `to_borsh()`: [5](#0-4) 

### Impact Explanation

An attacker who observes a valid `deploy_token` call on chain A can replay the identical `(signature, MetadataPayload)` tuple on chain B. The Borsh bytes are identical, the keccak digest is identical, and `_verify_borsh_signature` passes because both deployments share the same `omni_bridge_derived_address`. The token is then deployed on chain B without any chain-B-specific MPC authorization, violating the invariant that each deployment action is cryptographically bound to its destination chain. This is a signer/prover verification bypass enabling unauthorized deployer-equivalent actions. [6](#0-5) 

### Likelihood Explanation

The precondition — two OmniBridge deployments sharing the same `omni_bridge_derived_address` — is the **intended production configuration**: the MPC key is a single threshold-signature key shared across all supported chains. Any valid `deploy_token` signature ever broadcast on any chain is immediately replayable on every other chain. No privileged access is required; the attacker only needs to observe a public transaction.

### Recommendation

Pass `omni_bridge_chain_id` into `MetadataPayload::to_borsh()` and append it to the serialized bytes, mirroring the pattern already used in `TransferMessagePayload::to_borsh()`:

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

Then update the `deploy_token` call site:

```cairo
_verify_borsh_signature(ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature);
```

The MPC signing service must also be updated to include `chain_id` when producing `deploy_token` signatures.

### Proof of Concept

1. Deploy two OmniBridge instances — `BridgeA` (`omni_bridge_chain_id = 1`) and `BridgeB` (`omni_bridge_chain_id = 2`) — both initialized with the same `omni_bridge_derived_address`.
2. Obtain a valid MPC signature `sig_A` for a `MetadataPayload` (e.g., `token="usdc.near"`, `name="USD Coin"`, `symbol="USDC"`, `decimals=6`) targeting `BridgeA`.
3. Call `BridgeA.deploy_token(sig_A, payload)` — succeeds as expected.
4. Call `BridgeB.deploy_token(sig_A, payload)` with the **identical** `sig_A` and `payload`.
5. `MetadataPayload::to_borsh()` produces the same bytes on both chains; `_verify_borsh_signature` passes on `BridgeB`; the token is deployed on `BridgeB` without any chain-B-specific MPC authorization. [2](#0-1) [7](#0-6)

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

**File:** starknet/src/omni_bridge.cairo (L117-118)
```text
        omni_bridge_chain_id: u8,
        omni_bridge_derived_address: EthAddress,
```

**File:** starknet/src/omni_bridge.cairo (L202-209)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);

            let token_id_hash = compute_keccak_byte_array(@payload.token);
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
