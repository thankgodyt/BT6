Audit Report

## Title
Cross-Chain Replay of `MetadataPayload` Signature Enables Unauthorized Token Deployment — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`)

## Summary

The Borsh-encoded hash used to authorize `deployToken` (EVM) and `deploy_token` (Starknet) contains no chain identifier. Both chains verify against the same NEAR MPC-derived Ethereum address. A signature produced for a `deployToken` call on EVM is byte-for-byte valid on Starknet (and vice versa), allowing any observer to replay a public EVM transaction on Starknet and permanently occupy the `near_to_starknet_token` mapping slot for that NEAR token ID, blocking all future legitimate deployments.

## Finding Description

**EVM (`OmniBridge.sol` L142–153):** `deployToken` constructs the signed hash as:

```
keccak256( PayloadType::Metadata(1) | borsh(token) | borsh(name) | borsh(symbol) | decimals )
```

No `omniBridgeChainId` is included. Verification is against `nearBridgeDerivedAddress`.

**Starknet (`omni_bridge.cairo` L202–205, `bridge_types.cairo` L36–44):** `deploy_token` calls `payload.to_borsh()` (no `chain_id` argument), which produces:

```
PayloadType::Metadata(1) | encode_byte_array(token) | encode_byte_array(name) | encode_byte_array(symbol) | decimals
```

Verification is against `omni_bridge_derived_address` — the same NEAR MPC-derived Ethereum address used on EVM.

**Encoding equivalence:** Both `Borsh.encodeString` (EVM) and `borsh::encode_byte_array` (Starknet) emit a 4-byte LE length prefix followed by raw UTF-8 bytes. The `PayloadType::Metadata` discriminant is `1` on both chains. For any identical `(token, name, symbol, decimals)` tuple, the two hash inputs are byte-for-byte identical.

**Contrast with `fin_transfer`:** The EVM `finTransfer` hash includes `bytes1(omniBridgeChainId)` at two positions (L294, L297). The Starknet `fin_transfer` calls `payload.to_borsh(self.omni_bridge_chain_id.read())`, injecting `chain_id` at two positions (bridge_types.cairo L67, L70). The `deployToken` path has no equivalent binding.

**Exploit flow:**
1. Attacker observes any confirmed `deployToken(signatureData, metadata)` transaction on EVM (fully public calldata).
2. Attacker submits `deploy_token(signature, payload)` on Starknet with the identical `signatureData` and `metadata` values.
3. `_verify_borsh_signature` computes the same hash and recovers the same `omni_bridge_derived_address` — verification passes.
4. The token is deployed on Starknet and `near_to_starknet_token[keccak(token)]` is permanently written.
5. Every subsequent legitimate `deploy_token` call for that NEAR token ID reverts with `ERR_TOKEN_ALREADY_DEPLOYED`.
6. The attacker-controlled deployment becomes the canonical bridge token; `fin_transfer` will mint into it.

No existing guard prevents this: the only checks are the signature verification (which passes) and the `ERR_TOKEN_ALREADY_DEPLOYED` duplicate check (which the attacker triggers first).

## Impact Explanation

This is a **cross-chain replay / chain-domain separation flaw** and an **authorization bypass** matching two allowed Critical impact classes. The NEAR MPC authorized a deployment on chain A; the attacker uses that authorization to deploy on chain B without any additional MPC approval. The result is permanent: the `near_to_starknet_token` mapping cannot be overwritten, so the legitimate token owner can never deploy the canonical version of their token on Starknet. Additionally, the bridge will mint tokens into the attacker-deployed contract during `fin_transfer`, creating unauthorized bridge token creation with no recourse for the token owner.

## Likelihood Explanation

Exploitation requires zero privileges. All inputs — the signature bytes and the metadata payload — are visible in the calldata of any public `deployToken` transaction on EVM. The replay is a single permissionless contract call on Starknet. Every token that has been deployed on EVM but not yet on Starknet is permanently at risk from the moment its EVM deployment transaction is confirmed. The attack is repeatable for every such token.

## Recommendation

Include the destination chain ID in the `MetadataPayload` Borsh encoding, mirroring the pattern already used in `finTransfer`/`fin_transfer`.

**EVM (`OmniBridge.sol`):**
```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // add chain binding
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

**Starknet (`bridge_types.cairo`):** Change `MetadataPayloadTrait::to_borsh` to accept a `chain_id: u8` parameter and append it after the discriminant byte, then update the `deploy_token` call site to pass `self.omni_bridge_chain_id.read()`.

The NEAR MPC signing logic must also be updated to include the target chain ID in the payload it signs, so that signatures are chain-specific from the point of issuance.

## Proof of Concept

**Minimal test sequence (local testnet):**

1. Deploy both the EVM `OmniBridge` and the Starknet `OmniBridge` contracts, both initialized with the same `nearBridgeDerivedAddress` / `omni_bridge_derived_address` (a test key).
2. Using the test key, produce a valid `MetadataPayload` signature for `(token="wrap.near", name="Wrapped NEAR", symbol="wNEAR", decimals=24)` and call `deployToken` on EVM. Record the emitted `signatureData`.
3. Without any additional signing, call `deploy_token` on Starknet with the identical `signature` and `payload` values extracted from step 2.
4. Assert that the call succeeds (no revert), that `near_to_starknet_token[keccak("wrap.near")]` is now non-zero, and that a subsequent legitimate `deploy_token` call reverts with `ERR_TOKEN_ALREADY_DEPLOYED`.

The existing Starknet test helper `build_deploy_token_message` (test_contract.cairo L83–93) already constructs the hash without a chain ID, confirming the encoding is identical to the EVM path and that a cross-chain replay would pass verification.