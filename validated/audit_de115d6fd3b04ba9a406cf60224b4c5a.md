The code confirms the vulnerability. Let me trace through the exact logic:

**`MetadataPayload::to_borsh()`** encodes only: payload type byte, token, name, symbol, decimals — no chain identifier. [1](#0-0) 

**`TransferMessagePayload::to_borsh()`** takes `chain_id: u8` and appends it at two positions (lines 67 and 70). [2](#0-1) 

**`deploy_token()`** calls `payload.to_borsh()` with no chain argument, then passes the result directly to `_verify_borsh_signature`. [3](#0-2) 

**`_verify_borsh_signature()`** verifies the keccak digest against `self.omni_bridge_derived_address.read()` — a single stored Ethereum address. [4](#0-3) 

The `omni_bridge_derived_address` is a constructor parameter, not derived per-chain inside the contract. [5](#0-4) 

---

### Title
`MetadataPayload::to_borsh()` Omits Chain ID, Enabling Cross-Chain `deploy_token` Signature Replay — (`starknet/src/bridge_types.cairo`)

### Summary
`MetadataPayload::to_borsh()` produces a Borsh encoding that contains no chain identifier. `_verify_borsh_signature` checks only that the keccak digest was signed by `omni_bridge_derived_address`. Any two OmniBridge deployments sharing the same MPC-derived address (the standard configuration) will accept the identical signature for `deploy_token`, allowing a signature obtained for chain A to deploy an unauthorized bridge token on chain B.

### Finding Description
`TransferMessagePayload::to_borsh(chain_id)` correctly binds the payload to a specific chain by embedding `chain_id` twice in the serialized bytes (lines 67, 70 of `bridge_types.cairo`). `MetadataPayload::to_borsh()` has no such parameter and no chain binding whatsoever (lines 36–44). Because `deploy_token` calls `payload.to_borsh()` without passing `omni_bridge_chain_id` (line 205 of `omni_bridge.cairo`), the Borsh bytes — and therefore the keccak digest — are byte-for-byte identical for the same token metadata across every deployment that shares the same `omni_bridge_derived_address`. `_verify_borsh_signature` (lines 398–406) has no additional domain separator; it only checks the Ethereum ECDSA signature against the stored derived address. The signature therefore passes on every such deployment.

### Impact Explanation
An attacker who observes (or obtains) a valid `deploy_token` signature for chain A can call `deploy_token` on chain B with the same `(signature, payload)` tuple. The bridge contract on chain B will:
1. Accept the signature as valid MPC authorization.
2. Register the token in `near_to_starknet_token` and `starknet_to_near_token`.
3. Deploy a bridge token contract that the bridge can freely `mint` and `burn`.

Once the token is registered as a bridge token on chain B, any subsequent legitimate `fin_transfer` call for that NEAR token ID on chain B will mint to the attacker-deployed contract. This constitutes an authorization bypass enabling deployer-equivalent actions without chain-B-specific MPC consent, matching the Critical scope: *"Unauthorized transaction, authorization bypass … that lets an attacker execute bridge, token, deployer … actions."*

### Likelihood Explanation
The precondition — two deployments sharing the same `omni_bridge_derived_address` — is the **expected** production configuration, not an edge case. The NEAR MPC service issues a single derived Ethereum address used across all supported chains. `deploy_token` signatures are observable on-chain (emitted as `DeployToken` events on chain A) or can be obtained by any user who triggers the MPC flow. No privileged access is required beyond watching chain A.

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

Update `deploy_token` to pass `self.omni_bridge_chain_id.read()` to `to_borsh`, and update the MPC signing logic to include the destination chain ID when producing `deploy_token` signatures.

### Proof of Concept
1. Deploy `OmniBridge` at address `B_A` with `omni_bridge_chain_id = 1`, `omni_bridge_derived_address = MPC_ADDR`.
2. Deploy `OmniBridge` at address `B_B` with `omni_bridge_chain_id = 2`, `omni_bridge_derived_address = MPC_ADDR` (same key).
3. Obtain a valid `(signature_A, payload)` for `deploy_token` on `B_A` (e.g., by observing the on-chain call or triggering the MPC flow for chain A).
4. Call `B_B.deploy_token(signature_A, payload)`.
5. `payload.to_borsh()` produces identical bytes on both contracts; `_verify_borsh_signature` passes; the token is deployed on `B_B` without any chain-B MPC authorization.
6. Assert `B_B.get_token_address(payload.token) != 0` — token is live on chain B.

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

**File:** starknet/src/omni_bridge.cairo (L122-132)
```text
    #[constructor]
    fn constructor(
        ref self: ContractState,
        omni_bridge_derived_address: EthAddress,
        omni_bridge_chain_id: u8,
        token_class_hash: ClassHash,
        default_admin: ContractAddress,
        strk_token_address: ContractAddress,
    ) {
        self.omni_bridge_derived_address.write(omni_bridge_derived_address);
        self.omni_bridge_chain_id.write(omni_bridge_chain_id);
```

**File:** starknet/src/omni_bridge.cairo (L202-206)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);

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
