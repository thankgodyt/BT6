Audit Report

## Title
Cross-Chain Replay of `deployToken` Signed Message Due to Missing Chain ID in Payload — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
The `deployToken` function in `OmniBridge.sol` verifies a NEAR-MPC-signed payload that contains only `{PayloadType.Metadata, token, name, symbol, decimals}` with no chain-binding field. Because the same `nearBridgeDerivedAddress` is used across every EVM deployment of the bridge, a valid `deployToken` signature produced for one chain can be replayed verbatim on any other EVM chain. The same structural omission exists in the Solana and Starknet `deploy_token` paths. A successful replay permanently blocks legitimate token deployment on the target chain, freezing any user funds that were bridged targeting that chain.

## Finding Description

**Root cause — EVM:** The borsh-encoded payload hashed and signed by NEAR MPC is:

```
PayloadType.Metadata || token || name || symbol || decimals
``` [1](#0-0) 

No `omniBridgeChainId` or contract address is included. By contrast, `finTransfer` encodes `omniBridgeChainId` **twice** in its payload, explicitly binding the signature to a specific chain: [2](#0-1) 

**Root cause — NEAR signing side:** `log_metadata_callback` constructs a `MetadataPayload` with fields `{prefix, token, name, symbol, decimals}` and submits `keccak256(borsh(MetadataPayload))` to MPC for signing — no chain ID is included at the signing origin either: [3](#0-2) 

The `MetadataPayload` struct itself contains no chain field: [4](#0-3) 

**Root cause — Solana:** `DeployTokenPayload::serialize_for_near` writes `IncomingMessageType::Metadata` followed by borsh of `{token, name, symbol, decimals}` — no `SOLANA_OMNI_BRIDGE_CHAIN_ID`: [5](#0-4) 

Compare with `FinalizeTransferPayload::serialize_for_near`, which writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` at both the token and recipient positions: [6](#0-5) 

**Root cause — Starknet:** `MetadataPayload::to_borsh()` encodes `PayloadType::Metadata || token || name || symbol || decimals` with no chain ID byte: [7](#0-6) 

While `TransferMessagePayload::to_borsh(chain_id)` takes and encodes `chain_id` twice: [8](#0-7) 

**Why existing checks fail:** The only guard after signature verification is:

```solidity
require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST");
``` [9](#0-8) 

On a target chain where the token has not yet been deployed, `nearToEthToken[metadata.token]` is `address(0)` and `isBridgeToken[address(0)]` is `false`, so the check passes. The signature check also passes because `nearBridgeDerivedAddress` is the same key across all EVM deployments (confirmed by deployment artifacts for Arbitrum, Base, Polygon, BSC all referencing the same derived address). [10](#0-9) 

## Impact Explanation

This is a **Critical** cross-chain replay / chain-domain separation flaw. After a successful replay on chain B:

- `isBridgeToken`, `nearToEthToken`, and `ethToNearToken` are set on chain B for a token address that NEAR never registered for chain B.
- When NEAR later attempts to legitimately deploy the same token on chain B, the call reverts with `"ERR_TOKEN_EXIST"`.
- Any user who has locked tokens on NEAR intending to bridge to chain B cannot receive them — their funds are frozen on NEAR.
- The `removeCustomToken` admin escape hatch exists but the attacker can immediately re-replay the same signature after cleanup, making remediation a persistent race condition.

This matches the allowed Critical impact: *"Cross-chain replay … or chain/domain separation flaw enabling invalid finalization"* and *"permanent freezing of bridged funds."*

## Likelihood Explanation

The attack requires no special privilege. Any observer of a public EVM transaction can extract `signatureData` and `metadata` from a confirmed `deployToken` call on chain A and replay it on chain B. The attacker needs only a funded wallet on the target chain to pay gas. The bridge is deployed on Ethereum, Base, Arbitrum, BNB, and Polygon — all sharing the same `nearBridgeDerivedAddress` — giving a wide replay surface. The attack can be executed in the same block as the original transaction.

## Recommendation

Include the destination chain ID in the signed payload for `deployToken`, mirroring the pattern already used in `finTransfer`. For EVM:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // ADD THIS
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the equivalent fix in `DeployTokenPayload::serialize_for_near` on Solana (write `SOLANA_OMNI_BRIDGE_CHAIN_ID` before the token fields) and in `MetadataPayload::to_borsh` on Starknet. The NEAR `log_metadata_callback` must include the target chain ID in the `MetadataPayload` submitted to MPC so that signatures are chain-scoped from the origin.

## Proof of Concept

1. NEAR MPC signs a `deployToken` message for Ethereum. A relayer submits it; the transaction is confirmed and publicly visible on-chain.
2. Attacker extracts `signatureData` and `metadata` from the Ethereum transaction calldata.
3. Attacker calls `deployToken(signatureData, metadata)` on the Base `OmniBridge` contract.
4. Verification passes: `ECDSA.recover(keccak256(borshEncoded), signatureData) == nearBridgeDerivedAddress` ✓ (same key, identical payload bytes, no chain ID in hash).
5. `isBridgeToken[nearToEthToken[metadata.token]]` is `false` on Base ✓.
6. A new `ERC1967Proxy` is deployed on Base; `isBridgeToken`, `nearToEthToken`, `ethToNearToken` are set with the attacker-triggered token address.
7. NEAR later attempts to deploy the same token on Base via the normal flow. The call reverts: `"ERR_TOKEN_EXIST"`.
8. The token is permanently undeployable on Base through the legitimate path; any user who bridges that token targeting Base has their funds frozen on NEAR.

**Minimal test plan:** Fork Base and Ethereum mainnet (or use local Hardhat instances with the same `nearBridgeDerivedAddress`). Deploy `OmniBridge` on both with the same derived address. Call `deployToken` on instance A with a valid test signature. Extract the calldata. Call `deployToken` on instance B with the identical calldata. Assert it succeeds. Then attempt the legitimate `deployToken` on instance B and assert it reverts with `"ERR_TOKEN_EXIST"`.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L142-149)
```text
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(metadata.token),
            Borsh.encodeString(metadata.name),
            Borsh.encodeString(metadata.symbol),
            bytes1(metadata.decimals)
        );
        bytes32 hashed = keccak256(borshEncoded);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L151-153)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L155-158)
```text
        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-309)
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
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);
```

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

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L29-36)
```rust
        // 3. token
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. recipient
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
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
