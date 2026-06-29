Audit Report

## Title
Missing Chain ID in `deployToken` Message Hash Enables Cross-Chain Signature Replay — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
The `deployToken` function in `OmniBridge.sol` constructs a Borsh-encoded hash that omits `omniBridgeChainId`, while the analogous `finTransfer` function includes it twice. Because the Omni Bridge is deployed on multiple EVM chains sharing the same `nearBridgeDerivedAddress`, a valid MPC-signed `deployToken` signature obtained for one chain is accepted verbatim on every other EVM chain. This constitutes a chain/domain separation flaw enabling unauthorized token deployer actions and permanent registry corruption across all EVM spokes.

## Finding Description
`deployToken` in `OmniBridge.sol` hashes only `PayloadType.Metadata | token | name | symbol | decimals`: [1](#0-0) 

`finTransfer` in the same contract embeds `omniBridgeChainId` twice in its hash, demonstrating the intended pattern: [2](#0-1) 

The same asymmetry exists on Starknet. `deploy_token` calls `payload.to_borsh()` with no chain argument: [3](#0-2) 

While `fin_transfer` passes the chain ID: [4](#0-3) 

`MetadataPayload::to_borsh` in Cairo contains no chain ID field: [5](#0-4) 

`DeployTokenPayload::serialize_for_near` on Solana likewise omits any chain discriminator: [6](#0-5) 

On the NEAR side, `deploy_token_callback` only verifies that the emitter address matches the registered factory for the emitting chain — it does not verify that NEAR MPC explicitly authorized deployment on that specific chain: [7](#0-6) 

Because all EVM deployments share the same `nearBridgeDerivedAddress` and the hash is chain-agnostic, `ECDSA.recover` returns the same valid signer on every chain for the same `(signatureData, metadata)` tuple. There are no nonces, no chain IDs, and no other replay guards in `deployToken`.

## Impact Explanation
This is a **Critical** chain/domain separation flaw. An attacker can replay a single MPC-signed `deployToken` call across all other EVM spokes without any additional MPC authorization. Consequences include:

1. **Unauthorized token deployer action**: NEAR MPC authorized deployment on chain A only; the attacker causes deployment on chains B, C, D, etc.
2. **Permanent registry corruption**: Once `nearToEthToken[metadata.token]` is set on chain B via replay, the guard `require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST")` permanently blocks the legitimate relayer from ever deploying that token on chain B through the normal flow.
3. **Unauthorized NEAR-side registration**: The attacker can submit the replayed chain's `DeployToken` event as proof to NEAR's `deploy_token`, which `deploy_token_callback` accepts because the emitter is a legitimately registered factory.

This matches the allowed impact class: *Unauthorized transaction / authorization bypass that lets an attacker execute token deployer actions*, and *Cross-chain replay / chain/domain separation flaw enabling invalid finalization*.

## Likelihood Explanation
Exploitation requires no funds, no special role, and no private key. The attacker only needs to: (a) observe a legitimate `deployToken` transaction on any one EVM chain via public mempool or on-chain events, and (b) submit the identical calldata to the other chains via public RPC. The Omni Bridge is live on at least five EVM networks simultaneously, making the replay surface wide and the attack immediately repeatable for every token deployment event.

## Recommendation
Include `omniBridgeChainId` in the Borsh-encoded payload for `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // ← add this
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the same fix to `MetadataPayload::to_borsh` in `starknet/src/bridge_types.cairo` (add a `chain_id: u8` parameter and prepend it after the payload type byte) and to `DeployTokenPayload::serialize_for_near` in `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs` (write `SOLANA_OMNI_BRIDGE_CHAIN_ID` after the message type byte). The NEAR MPC signing side must include the destination chain ID in the signed bytes correspondingly.

## Proof of Concept

1. Monitor the Ethereum `OmniBridge` for a `deployToken(sig, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` transaction.
2. Copy `sig` and the `metadata` struct verbatim.
3. Call `deployToken(sig, metadata)` on Arbitrum's `OmniBridge`. `ECDSA.recover` returns `nearBridgeDerivedAddress` because the hash is identical — the check at L151 passes.
4. `usdc.near` is now deployed on Arbitrum without NEAR MPC authorization for Arbitrum; `nearToEthToken["usdc.near"]` is set on Arbitrum.
5. Submit the Arbitrum `DeployToken` event proof to NEAR's `deploy_token`. `deploy_token_callback` at L1159–1162 accepts it because Arbitrum's `OmniBridge` is a registered factory.
6. Any future legitimate attempt to deploy `usdc.near` on Arbitrum reverts with `"ERR_TOKEN_EXIST"` at L155–158.
7. Repeat steps 3–6 for Base, Polygon, BNB, and any other registered EVM spoke using the same single signature.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-313)
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

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
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

**File:** near/omni-bridge/src/lib.rs (L1155-1174)
```rust
        let Ok(ProverResult::LogMetadata(metadata)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        let chain = metadata.emitter_address.get_chain();
        require!(
            self.factories.get(&chain) == Some(metadata.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
```
