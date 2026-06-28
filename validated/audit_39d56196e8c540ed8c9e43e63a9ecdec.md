### Title
Cross-Chain Replay of `deploy_token` Signatures Enables Unauthorized Token Deployment on Any Bridge Chain — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The Borsh-encoded payload signed by the NEAR MPC for `deploy_token` / `deployToken` operations does not include a destination chain identifier. Because the encoding is byte-for-byte identical across EVM, Starknet, and Solana, a valid NEAR MPC signature obtained for one chain can be replayed verbatim on every other supported chain. Any unprivileged observer can extract the signature from the NEAR event log and call `deployToken` / `deploy_token` on any chain where the token has not yet been deployed, without the bridge operator's approval.

---

### Finding Description

**Root cause — missing chain ID in the `deploy_token` signed payload**

The `fin_transfer` path correctly binds the signed payload to a specific chain by embedding the `omniBridgeChainId` / `SOLANA_OMNI_BRIDGE_CHAIN_ID` in the Borsh encoding. The `deploy_token` path does not.

**EVM** (`OmniBridge.sol` lines 142–149):
```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)          // ← no omniBridgeChainId
);
bytes32 hashed = keccak256(borshEncoded);
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) revert InvalidSignature();
``` [1](#0-0) 

**Starknet** (`omni_bridge.cairo` line 205) calls `payload.to_borsh()` with no chain-ID argument:
```cairo
_verify_borsh_signature(ref self, @payload.to_borsh(), signature);
``` [2](#0-1) 

`MetadataPayload.to_borsh()` in `bridge_types.cairo` encodes only `[PayloadType::Metadata, token, name, symbol, decimals]`: [3](#0-2) 

**Solana** (`deploy_token.rs` lines 19–26) serializes `[IncomingMessageType::Metadata, token, name, symbol, decimals]` — again no chain ID: [4](#0-3) 

**Contrast with `fin_transfer`**, which correctly embeds `SOLANA_OMNI_BRIDGE_CHAIN_ID` before both the token address and the recipient address: [5](#0-4) 

And the Starknet `fin_transfer` passes `self.omni_bridge_chain_id.read()` into `to_borsh`: [6](#0-5) 

**Encoding identity across chains**

All three chains encode `Metadata` as byte value `1` (second variant of their respective `PayloadType` / `IncomingMessageType` enums). The full Borsh layout is therefore:

```
[0x01] [u32-LE len(token)] [token bytes]
       [u32-LE len(name)]  [name bytes]
       [u32-LE len(symbol)][symbol bytes]
       [decimals u8]
```

This is identical on EVM, Starknet, and Solana. A single NEAR MPC signature over this payload is valid on all three.

**Signature is publicly observable**

The NEAR bridge emits the MPC signature in `sign_log_metadata_callback` as a `LogMetadataEvent` log string, making it trivially extractable by any chain observer: [7](#0-6) 

**No role gate on `deploy_token`**

All three `deploy_token` entry points are permissionless — the only authorization check is the signature verification itself:
- EVM: `whenNotPaused(PAUSED_DEPLOY_TOKEN)` only
- Starknet: `assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), ...)` only
- Solana: signature check only [8](#0-7) [9](#0-8) 

---

### Impact Explanation

An attacker can deploy a bridged token on any chain where the bridge operator has not yet approved it, using a signature that was intended for a different chain. Concrete consequences:

1. **Unauthorized token registry entries**: `nearToEthToken` / `near_to_starknet_token` / the Solana wrapped-mint PDA are written for a token the operator never approved on that chain.
2. **Premature or incorrect token deployment**: If the operator intends to deploy a token with different decimals on different chains (e.g., USDC with 6 decimals on Ethereum vs. a different normalization on Solana), the attacker can force the wrong configuration by replaying the first-seen signature.
3. **Bridge routing to unintended tokens**: Once the token is registered, subsequent `finTransfer` calls from NEAR will mint/unlock against the attacker-forced token contract, potentially routing user funds to a chain or token the bridge infrastructure is not ready to support, causing permanent loss.

---

### Likelihood Explanation

- The NEAR MPC signature is emitted as a public on-chain event immediately after `sign_log_metadata` completes — no privileged access is needed to observe it.
- The replay call (`deployToken` / `deploy_token`) is permissionless on all three chains.
- The attack requires only: (a) monitoring NEAR events, (b) submitting one transaction on the target chain. This is trivially automatable.

---

### Recommendation

Include the destination chain ID in the `deploy_token` signed payload, mirroring the pattern already used by `fin_transfer`. For example, on EVM:

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

Apply the equivalent change to `MetadataPayload.to_borsh()` on Starknet (pass and embed `omni_bridge_chain_id`) and to `DeployTokenPayload::serialize_for_near` on Solana (write `SOLANA_OMNI_BRIDGE_CHAIN_ID` before the token fields). The NEAR bridge's `sign_log_metadata` must also be updated to include the target chain ID in the payload it submits to the MPC signer, so that signatures are chain-scoped from the point of creation.

---

### Proof of Concept

1. Bridge operator calls `log_metadata` on Ethereum for token `"usdc.near"` (decimals = 6). NEAR bridge calls MPC signer and emits `LogMetadataEvent` containing the ECDSA signature `S` over `keccak256([0x01, 9, "usdc.near", 4, "USDC", 4, "USDC", 6])`.

2. Attacker reads `S` from the NEAR event log.

3. Attacker calls `deployToken(S, {token:"usdc.near", name:"USDC", symbol:"USDC", decimals:6})` on Arbitrum (a different EVM chain). The Borsh encoding is identical; `ECDSA.recover` returns `nearBridgeDerivedAddress`; the token is deployed and registered.

4. Attacker repeats step 3 on Starknet and Solana using the same `S`.

5. All three chains now have `"usdc.near"` registered in their token mappings without the bridge operator ever approving those deployments. Any subsequent `finTransfer` from NEAR targeting those chains will mint against the attacker-forced token contracts.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-153)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
        if (tokenImplementationAddress == address(0)) {
            revert TokenImplementationNotSet();
        }
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

**File:** starknet/src/omni_bridge.cairo (L202-209)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);

            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');
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

**File:** starknet/src/bridge_types.cairo (L61-67)
```text
    fn to_borsh(self: @TransferMessagePayload, chain_id: u8) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::TransferMessage.into());
        borsh_bytes.append(@borsh::encode_u64(*self.destination_nonce));
        borsh_bytes.append_byte(*self.origin_chain);
        borsh_bytes.append(@borsh::encode_u64(*self.origin_nonce));
        borsh_bytes.append_byte(chain_id);
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

**File:** near/omni-bridge/src/lib.rs (L368-384)
```rust
    #[private]
    #[result_serializer(borsh)]
    pub fn sign_log_metadata_callback(
        &self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] metadata_payload: MetadataPayload,
    ) {
        if let Ok(signature) = call_result {
            env::log_str(
                &OmniBridgeEvent::LogMetadataEvent {
                    signature,
                    metadata_payload,
                }
                .to_log_string(),
            );
        }
    }
```
