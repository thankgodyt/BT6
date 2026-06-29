Audit Report

## Title
`MetadataPayload::to_borsh()` Omits Chain ID, Enabling Cross-Chain `deploy_token` Signature Replay — (`starknet/src/bridge_types.cairo`)

## Summary
`MetadataPayload::to_borsh()` serializes token metadata with no chain identifier, producing byte-for-byte identical Borsh output for the same token across every OmniBridge deployment that shares the same `omni_bridge_derived_address`. Because `_verify_borsh_signature` checks only that the keccak digest was signed by that stored address, a valid `deploy_token` signature obtained for chain A passes verification on chain B without any chain-B MPC authorization.

## Finding Description
`MetadataPayload::to_borsh()` (lines 36–44 of `bridge_types.cairo`) encodes only a payload-type byte, token, name, symbol, and decimals — no chain binding of any kind. [1](#0-0) 

By contrast, `TransferMessagePayload::to_borsh(chain_id: u8)` explicitly embeds `chain_id` at two positions (lines 67 and 70), binding each transfer signature to a specific destination chain. [2](#0-1) 

`deploy_token` calls `payload.to_borsh()` with no chain argument (line 205), then passes the result directly to `_verify_borsh_signature`. [3](#0-2) 

`_verify_borsh_signature` computes the keccak digest of those bytes and verifies the ECDSA signature against `self.omni_bridge_derived_address.read()` — a single stored Ethereum address with no additional domain separator. [4](#0-3) 

`omni_bridge_derived_address` is a plain constructor parameter, not derived per-chain inside the contract. [5](#0-4) 

The only guard inside `deploy_token` beyond the signature check is `ERR_TOKEN_ALREADY_DEPLOYED`, which is per-contract state and provides no cross-chain protection. [6](#0-5) 

## Impact Explanation
An attacker who observes or obtains a valid `(signature, payload)` for `deploy_token` on chain A can submit it unchanged to chain B. The bridge on chain B will accept the signature as valid MPC authorization, register the NEAR token ID in `near_to_starknet_token` / `starknet_to_near_token`, and deploy a bridge token contract that the bridge can freely `mint` and `burn` — all without any chain-B MPC consent. This is a concrete authorization bypass matching the Critical scope: *"Unauthorized transaction, authorization bypass… that lets an attacker execute bridge, token, deployer… actions."* Once the token is registered, any subsequent legitimate `fin_transfer` for that NEAR token on chain B will mint against the attacker-replayed contract, and any attempt by the legitimate MPC to deploy the same token on chain B will fail with `ERR_TOKEN_ALREADY_DEPLOYED`, permanently blocking the authorized deployment path.

## Likelihood Explanation
The required precondition — two deployments sharing the same `omni_bridge_derived_address` — is the standard production configuration for a cross-chain bridge using NEAR MPC, not an edge case. `deploy_token` signatures are observable on-chain via emitted `DeployToken` events or can be obtained by any user who triggers the MPC flow on chain A. No privileged access is required. The attack is repeatable for every token deployed on chain A.

## Recommendation
Pass `omni_bridge_chain_id` into `MetadataPayload::to_borsh()` and append it to the serialized bytes, mirroring the pattern already used in `TransferMessagePayload::to_borsh()`:

```cairo
fn to_borsh(self: @MetadataPayload, chain_id: u8) -> ByteArray {
    let mut borsh_bytes: ByteArray = Default::default();
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append_byte(chain_id);  // <-- add this
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
    borsh_bytes
}
```

Update `deploy_token` to pass `self.omni_bridge_chain_id.read()` to `to_borsh`, and update the MPC signing logic to include the destination chain ID when producing `deploy_token` signatures.

## Proof of Concept
1. Deploy `OmniBridge` at `B_A` with `omni_bridge_chain_id = 1`, `omni_bridge_derived_address = MPC_ADDR`.
2. Deploy `OmniBridge` at `B_B` with `omni_bridge_chain_id = 2`, `omni_bridge_derived_address = MPC_ADDR` (same key).
3. Obtain a valid `(signature_A, payload)` for `deploy_token` on `B_A` (e.g., by observing the on-chain `DeployToken` event or triggering the MPC flow for chain A).
4. Call `B_B.deploy_token(signature_A, payload)`.
5. `payload.to_borsh()` produces identical bytes on both contracts; `_verify_borsh_signature` passes; the token is deployed on `B_B` without any chain-B MPC authorization.
6. Assert `B_B.get_token_address(payload.token) != 0` — token is live on chain B.
7. Confirm that a subsequent legitimate call to `B_B.deploy_token` for the same token fails with `ERR_TOKEN_ALREADY_DEPLOYED`, permanently blocking the authorized deployment.

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

**File:** starknet/src/omni_bridge.cairo (L202-205)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
```

**File:** starknet/src/omni_bridge.cairo (L207-209)
```text
            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');
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
