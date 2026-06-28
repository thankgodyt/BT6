### Title
Missing Chain ID in `deploy_token` Signed Payload Enables Cross-Chain Signature Replay — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/bridge_types.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The `deploy_token` signature verification across all three spoke implementations (EVM, Starknet, Solana) hashes a `MetadataPayload` that contains no destination chain identifier. Because the same MPC-derived address (`nearBridgeDerivedAddress`) is used on every chain, a single valid MPC signature authorizing token deployment on chain A is cryptographically valid on every other chain where the bridge is deployed. An unprivileged attacker who observes a legitimate `deployToken` transaction on one chain can replay the identical signature on any other chain, deploying the bridge token there without MPC authorization for that chain.

---

### Finding Description

**EVM — `OmniBridge.sol::deployToken` (lines 142–151)**

The signed message is constructed as:

```
keccak256(PayloadType.Metadata || token || name || symbol || decimals)
```

No `omniBridgeChainId` is included. [1](#0-0) 

Contrast with `finTransfer` (lines 289–311), which embeds `omniBridgeChainId` twice in the signed blob: [2](#0-1) 

**Starknet — `bridge_types.cairo::MetadataPayloadImpl::to_borsh` (lines 36–44)**

`MetadataPayload::to_borsh()` serializes `PayloadType::Metadata || token || name || symbol || decimals` with no chain ID argument: [3](#0-2) 

`deploy_token` in `omni_bridge.cairo` calls `_verify_borsh_signature(ref self, @payload.to_borsh(), signature)` — no chain ID passed: [4](#0-3) 

Contrast with `fin_transfer`, which passes `self.omni_bridge_chain_id.read()` into `to_borsh`: [5](#0-4) 

And `TransferMessagePayload::to_borsh` encodes `chain_id` twice: [6](#0-5) 

**Solana — `deploy_token.rs::DeployTokenPayload::serialize_for_near` (lines 19–26)**

Serializes `IncomingMessageType::Metadata || token || name || symbol || decimals` — no `SOLANA_OMNI_BRIDGE_CHAIN_ID`: [7](#0-6) 

Contrast with `FinalizeTransferPayload::serialize_for_near`, which writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` for both the token and recipient fields: [8](#0-7) 

The generic `SignedPayload::verify_signature` simply hashes whatever `serialize_for_near` returns and checks it against `derived_near_bridge_address`: [9](#0-8) 

---

### Impact Explanation

The MPC-derived bridge address is the same across all chains (it is a deterministic derivation, not chain-specific). A `MetadataPayload` signature produced by the MPC for Ethereum is byte-for-byte identical to what any other chain would verify. An attacker can:

1. Observe a legitimate `deployToken(sig, payload)` call on chain A (e.g., Ethereum).
2. Submit the same `(sig, payload)` to chain B (e.g., Arbitrum, Base, Starknet, Solana).
3. The signature passes verification on chain B because the hash is identical.
4. A bridge token is deployed on chain B and registered (`isBridgeToken = true`, `nearToEthToken` mapping set) without MPC authorization for chain B.
5. If chain B's OmniBridge is a registered factory on NEAR, the NEAR bridge processes the resulting `DeployToken` event and registers the token for chain B, enabling subsequent `finTransfer` flows to that chain.

This is a chain/domain separation flaw and an authorization bypass: the MPC authorized deployment on chain A only, but the attacker extends that authorization to chain B. Additionally, once the token is deployed via replay, the legitimate relayer cannot deploy it again on chain B (`ERR_TOKEN_EXIST` / `ERR_TOKEN_ALREADY_DEPLOYED`), permanently blocking the authorized deployment path.

---

### Likelihood Explanation

All bridge deployments share the same `nearBridgeDerivedAddress`. Every `deployToken` transaction is public on-chain. Any observer can extract the signature and payload and submit them to any other chain where the bridge is deployed. No privileged access, leaked keys, or special tooling is required — only a standard transaction submission.

---

### Recommendation

Include the destination chain identifier in the signed `MetadataPayload` hash, mirroring the pattern already used in `finTransfer`/`fin_transfer`/`finalize_transfer`:

- **EVM**: Add `bytes1(omniBridgeChainId)` to the `borshEncoded` blob in `deployToken` before hashing.
- **Starknet**: Add a `chain_id: u8` parameter to `MetadataPayload::to_borsh` and append it to the serialized bytes; pass `self.omni_bridge_chain_id.read()` at the call site in `deploy_token`.
- **Solana**: Write `SOLANA_OMNI_BRIDGE_CHAIN_ID` into `DeployTokenPayload::serialize_for_near` before the token fields, matching the pattern in `FinalizeTransferPayload`.

---

### Proof of Concept

**EVM cross-chain replay:**

```typescript
// 1. Observe legitimate deployToken on Ethereum
const ethereumTx = await ethProvider.getTransaction(knownDeployTxHash);
const { signatureData, metadata } = decodeDeployTokenCalldata(ethereumTx.data);

// 2. Replay on Arbitrum — same sig, same payload, passes verification
const arbitrumBridge = OmniBridge__factory.connect(ARBITRUM_BRIDGE_ADDR, arbitrumSigner);
await arbitrumBridge.deployToken(signatureData, metadata);
// Succeeds: ECDSA.recover(keccak256(borshEncoded), signatureData) == nearBridgeDerivedAddress
// Token is now deployed on Arbitrum without MPC authorization for Arbitrum
```

The hash verified on Arbitrum is `keccak256(0x01 || borsh(token) || borsh(name) || borsh(symbol) || decimals)` — identical to Ethereum's hash because `omniBridgeChainId` is absent from both.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L142-152)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-311)
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

**File:** solana/programs/bridge_token_factory/src/state/message/deploy_token.rs (L19-26)
```rust
    fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
        IncomingMessageType::Metadata.serialize(&mut writer)?;
        self.serialize(&mut writer)?; // borsh encoding
        writer
            .into_inner()
            .map_err(|_| error!(ErrorCode::InvalidArgs))
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

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L23-47)
```rust
impl<P: Payload> SignedPayload<P> {
    pub fn verify_signature(
        &self,
        params: P::AdditionalParams,
        derived_near_bridge_address: &[u8; 64],
    ) -> Result<()> {
        let serialized = self.payload.serialize_for_near(params)?;
        let hash = keccak::hash(&serialized);

        let signature_bytes = &self.signature[0..64];

        let signature = libsecp256k1::Signature::parse_standard_slice(signature_bytes)
            .map_err(|_| ProgramError::InvalidArgument)?;
        require!(!signature.s.is_high(), ErrorCode::MalleableSignature);

        let signer = secp256k1_recover(&hash.to_bytes(), self.signature[64], signature_bytes)
            .map_err(|_| error!(ErrorCode::SignatureVerificationFailed))?;

        require!(
            signer.0 == *derived_near_bridge_address,
            ErrorCode::SignatureVerificationFailed
        );

        Ok(())
    }
```
