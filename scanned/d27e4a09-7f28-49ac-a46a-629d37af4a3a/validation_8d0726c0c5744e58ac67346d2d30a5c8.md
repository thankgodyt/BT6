### Title
Cross-Chain Replay of `deploy_token` Signatures Due to Missing Chain ID in Signed Message — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The `deploy_token` signed message on every foreign-chain bridge (EVM, Starknet, Solana) omits any chain identifier. A signature produced by the NEAR MPC for deploying a token on one chain is byte-for-byte valid on every other chain that uses the same borsh encoding. An attacker who observes a legitimate `deploy_token` transaction on one chain can replay the signature on any other supported chain, registering the token in that chain's bridge mapping without NEAR's intent.

---

### Finding Description

Every foreign-chain bridge verifies a NEAR MPC ECDSA signature over a borsh-encoded `MetadataPayload`. The encoding is identical across all three implementations:

**EVM** (`OmniBridge.sol`, lines 142–149):
```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
bytes32 hashed = keccak256(borshEncoded);
``` [1](#0-0) 

**Starknet** (`bridge_types.cairo`, `MetadataPayload.to_borsh`, lines 36–44):
```cairo
fn to_borsh(self: @MetadataPayload) -> ByteArray {
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
``` [2](#0-1) 

Called without a chain ID: `_verify_borsh_signature(ref self, @payload.to_borsh(), signature)`. [3](#0-2) 

**Solana** (`deploy_token.rs`, `serialize_for_near`, lines 19–27):
```rust
fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
    IncomingMessageType::Metadata.serialize(&mut writer)?;
    self.serialize(&mut writer)?; // borsh encoding: token + name + symbol + decimals
``` [4](#0-3) 

None of these include a chain ID, contract address, or any other domain separator.

**Contrast with `fin_transfer`**, which correctly binds the message to the destination chain. On EVM, `omniBridgeChainId` appears twice in the borsh encoding: [5](#0-4) 

On Starknet, `chain_id` is passed into `to_borsh`: [6](#0-5) 

On Solana, `SOLANA_OMNI_BRIDGE_CHAIN_ID` is written into the serialized payload: [7](#0-6) 

The `deploy_token` path has no equivalent protection.

---

### Impact Explanation

Once a relayer submits a legitimate `deployToken` transaction on any chain, the NEAR MPC signature is permanently public on-chain. An attacker can extract it and submit it to `deployToken`/`deploy_token` on any other supported chain (EVM L2s, Starknet, Solana) with the identical `MetadataPayload`. The signature will pass verification because the signed bytes are chain-agnostic.

Consequences:

1. **Token metadata binding confusion**: The token is registered in the unintended chain's bridge mapping (`nearToEthToken`, `near_to_starknet_token`, or the Solana mint PDA) as a valid bridge token. The bridge on that chain will treat it as a canonical wrapped token.
2. **Blocking legitimate deployment**: If the NEAR bridge later legitimately attempts to deploy the same token on that chain, the call reverts (`ERR_TOKEN_EXIST` / `ERR_TOKEN_ALREADY_DEPLOYED`), permanently preventing correct deployment.
3. **Unauthorized minting path**: If the NEAR bridge's `sign_transfer` does not gate on whether the token was explicitly registered for the destination chain, a user requesting a NEAR→UnintendedChain transfer would receive a valid `fin_transfer` signature. The unintended chain's bridge would then mint tokens against the phantom token contract, constituting unauthorized minting.

---

### Likelihood Explanation

**Low.** The attacker must monitor bridge transactions on at least one chain to extract a `deploy_token` signature, then submit it to another chain before the token is deployed there. No privileged access is required; the signature is fully public once the originating transaction is confirmed. The attack is straightforward for any party watching bridge activity.

---

### Recommendation

Include the destination chain ID in the `deploy_token` signed message, exactly as `fin_transfer` does. For EVM:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // <-- add this
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the equivalent change to `MetadataPayload.to_borsh()` in `starknet/src/bridge_types.cairo` (accepting `chain_id: u8` as a parameter) and to `DeployTokenPayload::serialize_for_near` in `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs` (writing `SOLANA_OMNI_BRIDGE_CHAIN_ID`). The NEAR MPC signing path must be updated to include the chain ID when constructing the payload to sign.

---

### Proof of Concept

1. NEAR MPC signs a `deploy_token` payload for token `"usdc.near"` (name `"USD Coin"`, symbol `"USDC"`, decimals `6`) targeting Ethereum. The borsh bytes are:
   `\x01 | len("usdc.near") | "usdc.near" | len("USD Coin") | "USD Coin" | len("USDC") | "USDC" | \x06`

2. Relayer calls `deployToken(sig, payload)` on Ethereum's `OmniBridge.sol`. Transaction is confirmed; `sig` is now public.

3. Attacker calls `deployToken(sig, payload)` on Arbitrum's `OmniBridge.sol` (same contract, different chain). The `keccak256` of the identical borsh bytes is identical; `ECDSA.recover` returns `nearBridgeDerivedAddress`; the check passes. [8](#0-7) 

4. A wrapped USDC token is deployed on Arbitrum and registered: `nearToEthToken["usdc.near"] = <phantom_address>`. [9](#0-8) 

5. Attacker repeats step 3 on Starknet's `omni_bridge.cairo` and Solana's `bridge_token_factory` using the same `sig` and `payload`. All three pass because `_verify_borsh_signature` / `verify_signature` hash the same chain-agnostic bytes. [10](#0-9) 

6. USDC is now registered as a bridge token on three unintended chains. Any subsequent legitimate `deployToken` for USDC on those chains will revert permanently.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
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

**File:** starknet/src/omni_bridge.cairo (L205-205)
```text
            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
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
