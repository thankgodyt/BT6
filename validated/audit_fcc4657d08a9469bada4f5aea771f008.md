Audit Report

## Title
Missing Chain ID in `deployToken` Borsh Payload Enables Cross-Chain Replay of Token Deployment — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/bridge_types.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

## Summary

The `deployToken` function in `OmniBridge.sol` constructs a Borsh-encoded payload for NEAR MPC signature verification that contains only token metadata (type byte, token ID, name, symbol, decimals) with no destination chain identifier. Because `nearBridgeDerivedAddress` is the same derived key across all EVM deployments, a valid `deployToken` signature produced for one chain is cryptographically valid on every other EVM chain. An unprivileged attacker can copy any on-chain `deployToken` calldata and replay it on all other EVM chains, permanently blocking legitimate NEAR-authorized deployment of that token on those chains. The same flaw exists in the Starknet and Solana bridge implementations.

## Finding Description

**Root cause — EVM (`OmniBridge.sol` L142–153):**

`deployToken` builds its signed payload as:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

No `omniBridgeChainId` is present. The recovered signer is compared to `nearBridgeDerivedAddress` (L151), which is the same Ethereum address on every EVM deployment.

**Contrast with `finTransfer` (`OmniBridge.sol` L289–298):**

`finTransfer` embeds `omniBridgeChainId` twice in its payload, binding the signature to the specific destination chain. `deployToken` has no equivalent binding.

**Starknet (`starknet/src/bridge_types.cairo` L36–44):**

`MetadataPayloadTrait::to_borsh` takes no `chain_id` parameter and encodes only the four metadata fields. `TransferMessagePayloadTrait::to_borsh` (L61–68) accepts and embeds `chain_id`. `deploy_token` in `omni_bridge.cairo` (L205) calls the chain-ID-free variant; `fin_transfer` (L252–254) correctly passes `self.omni_bridge_chain_id.read()`.

**Solana (`solana/programs/bridge_token_factory/src/state/message/deploy_token.rs` L19–27):**

`DeployTokenPayload::serialize_for_near` writes only the `IncomingMessageType::Metadata` discriminant followed by the raw Borsh-serialized struct fields — no chain constant is included.

**Exploit path:**

1. NEAR MPC signs `MetadataPayload{token, name, symbol, decimals}` for Ethereum. Relayer calls `OmniBridge.deployToken(sig, payload)` on Ethereum — succeeds.
2. Attacker copies `(sig, payload)` verbatim and calls `OmniBridge.deployToken(sig, payload)` on Arbitrum. The Borsh encoding is byte-for-byte identical; `ECDSA.recover` returns `nearBridgeDerivedAddress`; signature check passes.
3. `isBridgeToken[bridgeTokenProxy] = true`, `nearToEthToken[metadata.token] = bridgeTokenProxy`, and `ethToNearToken[bridgeTokenProxy] = metadata.token` are written on Arbitrum without NEAR ever authorizing deployment there.
4. When NEAR later attempts the legitimate deployment on Arbitrum, `require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST")` (L155–158) reverts. The token is permanently blocked from legitimate deployment on Arbitrum.

**Existing guards are insufficient:** The `ERR_TOKEN_EXIST` guard only prevents re-deployment on the *same* chain; it provides no protection against cross-chain replay. There is no nonce, no chain binding, and no other mechanism in the `deployToken` signature verification path that distinguishes one EVM chain from another.

## Impact Explanation

This is a **Critical** chain/domain separation flaw. Concretely:

- **Unauthorized token deployment**: An attacker causes a `BridgeToken` to be registered as a canonical bridge token on a chain that NEAR never authorized, bypassing the intended MPC-based deployment authorization model.
- **Permanent freezing of bridge functionality**: Once the attacker's replay sets `nearToEthToken[token]` and `isBridgeToken[proxy] = true` on a target chain, no future call to `deployToken` for that token can succeed on that chain. The NEAR bridge is permanently unable to legitimately register the token there, freezing the ability to bridge that asset to that chain.

This matches the allowed Critical impact class: *"Cross-chain replay … or chain/domain separation flaw enabling invalid finalization or double-spending"* and *"Unauthorized transaction … that lets an attacker execute bridge, token, deployer … actions."*

## Likelihood Explanation

The attack requires only: (1) monitoring any public EVM chain for a `deployToken` transaction (trivially observable via block explorers or mempool), and (2) submitting the identical calldata to any other EVM chain. No privileged access, leaked keys, off-chain coordination, or victim interaction is required. The bridge is live on at least five EVM chains (Ethereum, Arbitrum, Base, BNB, Polygon), so every new token deployment on any one chain is immediately replayable on the remaining four. Likelihood is **high**.

## Recommendation

Include `omniBridgeChainId` in the Borsh-encoded payload for `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // bind to destination chain
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the same fix to `MetadataPayloadTrait::to_borsh` in `starknet/src/bridge_types.cairo` (add a `chain_id: u8` parameter and append it after the type byte, matching `TransferMessagePayloadTrait::to_borsh`), update `deploy_token` in `starknet/src/omni_bridge.cairo` to pass `self.omni_bridge_chain_id.read()`, and include `SOLANA_OMNI_BRIDGE_CHAIN_ID` in `DeployTokenPayload::serialize_for_near` in `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`.

## Proof of Concept

**Minimal transaction-sequence test (private testnet):**

1. Deploy `OmniBridge` on two local EVM chains (chain A, chain B) with the same `nearBridgeDerivedAddress` and distinct `omniBridgeChainId` values.
2. Produce a valid NEAR MPC signature over `MetadataPayload{token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6}` (no chain ID in payload).
3. Call `OmniBridge.deployToken(sig, payload)` on chain A — succeeds; record `(sig, payload)`.
4. Call `OmniBridge.deployToken(sig, payload)` on chain B with the identical arguments — succeeds; `nearToEthToken["usdc.near"]` is now set on chain B.
5. Attempt a second `OmniBridge.deployToken` call on chain B with a fresh relayer submission — reverts with `ERR_TOKEN_EXIST`, confirming permanent blocking.

Steps 3–5 require no privileged access and are executable by any EOA. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L155-158)
```text
        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
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

**File:** starknet/src/bridge_types.cairo (L61-68)
```text
    fn to_borsh(self: @TransferMessagePayload, chain_id: u8) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::TransferMessage.into());
        borsh_bytes.append(@borsh::encode_u64(*self.destination_nonce));
        borsh_bytes.append_byte(*self.origin_chain);
        borsh_bytes.append(@borsh::encode_u64(*self.origin_nonce));
        borsh_bytes.append_byte(chain_id);
        borsh_bytes.append(@borsh::encode_address(*self.token_address));
```

**File:** starknet/src/omni_bridge.cairo (L202-205)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
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
