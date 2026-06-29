Audit Report

## Title
Cross-Chain Signature Replay on `deploy_token`/`deployToken` Due to Missing Chain ID in `MetadataPayload` — (`near/omni-bridge/src/lib.rs`, `evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

## Summary

The `MetadataPayload` signed by the NEAR MPC signer for `deploy_token`/`deployToken` contains no chain identifier. A valid MPC signature obtained on one chain (e.g., Ethereum) is byte-for-byte identical to what any other supported chain (Starknet, Solana, another EVM chain) would accept, because the borsh-encoded blob is chain-agnostic. An attacker can extract the signature from public calldata on one chain and replay it on any other chain to deploy a bridge token without operator authorization, permanently blocking the operator's legitimate deployment on that chain.

## Finding Description

**NEAR signing side (`near/omni-bridge/src/lib.rs` L341–351):**

`log_metadata_callback` constructs a `MetadataPayload` containing only `{prefix, token, name, symbol, decimals}` and requests an MPC signature over `keccak256(borsh(MetadataPayload))`:

```rust
let metadata_payload = MetadataPayload {
    prefix: PayloadType::Metadata,
    token: token_id.to_string(),
    name: metadata.name,
    symbol: metadata.symbol,
    decimals: metadata.decimals,
};
let payload = near_sdk::env::keccak256_array(
    borsh::to_vec(&metadata_payload).near_expect(BridgeError::Borsh),
);
``` [1](#0-0) 

The `MetadataPayload` struct (`near/omni-types/src/lib.rs` L694–702) has no `chain_id` field: [2](#0-1) 

**EVM verification (`evm/src/omni-bridge/contracts/OmniBridge.sol` L142–153):**

`deployToken` reconstructs the same chain-agnostic borsh blob — no `omniBridgeChainId` is included:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
``` [3](#0-2) 

In contrast, `finTransfer` explicitly encodes `bytes1(omniBridgeChainId)` twice: [4](#0-3) 

**Starknet verification (`starknet/src/bridge_types.cairo` L36–44 and `starknet/src/omni_bridge.cairo` L202–209):**

`MetadataPayloadTrait::to_borsh()` encodes only `{Metadata, token, name, symbol, decimals}`: [5](#0-4) 

`deploy_token` calls `_verify_borsh_signature(ref self, @payload.to_borsh(), signature)` — no chain ID argument: [6](#0-5) 

`fin_transfer` correctly passes `self.omni_bridge_chain_id.read()` to `to_borsh`: [7](#0-6) 

**Solana verification (`solana/programs/bridge_token_factory/src/state/message/deploy_token.rs` L19–27):**

`DeployTokenPayload::serialize_for_near` writes only `IncomingMessageType::Metadata` + payload fields — no `SOLANA_OMNI_BRIDGE_CHAIN_ID`: [8](#0-7) 

`FinalizeTransferPayload::serialize_for_near` writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` for both token and recipient: [9](#0-8) 

The root cause is a consistent omission across all four chains: the `MetadataPayload` borsh encoding is identical regardless of which destination chain is targeted, so a single MPC signature is universally valid on all chains simultaneously.

## Impact Explanation

This is a **chain/domain separation flaw enabling unauthorized bridge actions**, matching the Critical allowed impact: *"Cross-chain replay … or chain/domain separation flaw enabling invalid finalization or double-spending"* and *"Unauthorized transaction, authorization bypass … that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."*

Concrete consequences:
1. **Unauthorized token deployment**: An attacker deploys a bridge token on a chain where the operator has not authorized or configured infrastructure (relayers, liquidity, NEAR-side counterpart).
2. **Permanent registration conflict**: Once deployed, the token is registered in `near_to_starknet_token` / `nearToEthToken`. A subsequent legitimate deployment by the operator reverts with `ERR_TOKEN_ALREADY_DEPLOYED` / `ERR_TOKEN_EXIST`, permanently blocking the intended deployment flow.
3. **User fund loss**: Users who observe the `DeployToken` event and interact with the prematurely deployed token (e.g., calling `init_transfer` on Starknet) will lock funds in a bridge with no authorized relayer or NEAR-side counterpart, resulting in stuck or lost funds.

## Likelihood Explanation

The attack requires no special privilege. The `deployToken`/`deploy_token` signature is submitted as public calldata on the source chain and is trivially extractable by any on-chain observer. The attacker only needs to:
1. Watch for a `DeployToken` event on any supported chain.
2. Extract `signatureData`/`signature` from the transaction calldata.
3. Replay it on any other supported chain with the same `MetadataPayload` fields.

The bridge is live across Ethereum, Arbitrum, Base, Polygon, Starknet, and Solana simultaneously, making cross-chain replay straightforward and repeatable for every token deployment.

## Recommendation

Include the destination chain ID in `MetadataPayload` before signing, mirroring the pattern already used for `TransferMessagePayload`:

1. **NEAR side**: Add a `chain_id: ChainKind` field to `MetadataPayload` (or pass it as a parameter to `log_metadata_callback`) and include it in the borsh-serialized bytes before calling `keccak256`.
2. **EVM side**: Include `bytes1(omniBridgeChainId)` in the `borshEncoded` blob inside `deployToken`, matching the pattern in `finTransfer`.
3. **Starknet side**: Change `MetadataPayloadTrait::to_borsh()` to accept a `chain_id: u8` parameter and append it, matching `TransferMessagePayloadTrait::to_borsh(chain_id)`.
4. **Solana side**: Write `SOLANA_OMNI_BRIDGE_CHAIN_ID` into the serialized bytes inside `DeployTokenPayload::serialize_for_near()`, matching `FinalizeTransferPayload::serialize_for_near()`.

## Proof of Concept

1. Operator calls `log_metadata("token.near")` on the NEAR bridge. MPC signs `keccak256(borsh({Metadata, "token.near", "Token", "TKN", 18}))` → `sig`.
2. Relayer submits `deployToken(sig, {token: "token.near", name: "Token", symbol: "TKN", decimals: 18})` on Ethereum. Token deployed at `addr_eth`. Signature `sig` is now public in Ethereum calldata.
3. Attacker extracts `sig` from Ethereum calldata (e.g., via `eth_getTransactionByHash`).
4. Attacker calls `deploy_token(sig, MetadataPayload{token: "token.near", name: "Token", symbol: "TKN", decimals: 18})` on the Starknet bridge. Starknet computes `keccak256(borsh({Metadata, "token.near", "Token", "TKN", 18}))` — identical hash — and `_verify_borsh_signature` passes. Token is deployed on Starknet without operator authorization.
5. When the operator later tries to deploy the token on Starknet, the call reverts with `ERR_TOKEN_ALREADY_DEPLOYED`.
6. The same replay works on Solana and any other EVM chain (Arbitrum, Base, Polygon) using the same `sig`.

A reproducible test can be written as a Hardhat/Foundry integration test: deploy two `OmniBridge` instances with different `omniBridgeChainId` values, generate a valid `deployToken` signature for chain A, and confirm it is accepted by chain B's `deployToken` without modification.

### Citations

**File:** near/omni-bridge/src/lib.rs (L341-351)
```rust
        let metadata_payload = MetadataPayload {
            prefix: PayloadType::Metadata,
            token: token_id.to_string(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
        };

        let payload = near_sdk::env::keccak256_array(
            borsh::to_vec(&metadata_payload).near_expect(BridgeError::Borsh),
        );
```

**File:** near/omni-types/src/lib.rs (L694-702)
```rust
#[near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct MetadataPayload {
    pub prefix: PayloadType,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L142-153)
```text
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(metadata.token),
            Borsh.encodeString(metadata.name),
            Borsh.encodeString(metadata.symbol),
            bytes1(metadata.decimals)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-298)
```text
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
```

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

**File:** solana/programs/bridge_token_factory/src/state/message/deploy_token.rs (L19-27)
```rust
    fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
        IncomingMessageType::Metadata.serialize(&mut writer)?;
        self.serialize(&mut writer)?; // borsh encoding
        writer
            .into_inner()
            .map_err(|_| error!(ErrorCode::InvalidArgs))
    }
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L30-36)
```rust
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. recipient
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
```
