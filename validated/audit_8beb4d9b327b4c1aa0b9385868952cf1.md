### Title
Cross-Chain Replay of `deploy_token` Signatures Due to Missing Chain ID in MetadataPayload Hash — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/bridge_types.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The `deploy_token` / `deployToken` signature verification across EVM, Starknet, and Solana does not bind the signed message to a specific destination chain. A valid MPC-signed `MetadataPayload` obtained for one chain can be replayed verbatim on any other supported chain that shares the same `nearBridgeDerivedAddress`, enabling unauthorized token deployment without a new MPC authorization.

---

### Finding Description

Every `finTransfer`/`fin_transfer`/`finalize_transfer` path correctly encodes the destination chain ID into the signed Borsh payload, preventing cross-chain replay of transfer signatures. However, the `deployToken`/`deploy_token` path omits the chain ID entirely from the signed message.

**EVM `deployToken` — no chain ID in hash:**

```solidity
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
``` [1](#0-0) 

**Starknet `MetadataPayload::to_borsh()` — no chain ID:**

```cairo
fn to_borsh(self: @MetadataPayload) -> ByteArray {
    let mut borsh_bytes: ByteArray = Default::default();
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
    borsh_bytes
}
``` [2](#0-1) 

Called without chain ID in `deploy_token`: [3](#0-2) 

**Solana `DeployTokenPayload::serialize_for_near()` — no chain ID:**

```rust
fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
    IncomingMessageType::Metadata.serialize(&mut writer)?;
    self.serialize(&mut writer)?; // borsh encoding — no chain ID
    ...
}
``` [4](#0-3) 

**Contrast — `finTransfer` on EVM correctly includes `omniBridgeChainId` twice:** [5](#0-4) 

**Contrast — Starknet `TransferMessagePayload::to_borsh(chain_id)` correctly includes chain ID:** [6](#0-5) 

**Contrast — Solana `FinalizeTransferPayload::serialize_for_near` correctly includes `SOLANA_OMNI_BRIDGE_CHAIN_ID`:** [7](#0-6) 

The asymmetry is explicit: transfer finalization is chain-bound; token deployment is not.

---

### Impact Explanation

All bridge deployments across EVM chains (Ethereum, Arbitrum, Base, Polygon, BNB) and Starknet share the same `nearBridgeDerivedAddress` / `omni_bridge_derived_address` — the NEAR MPC-derived key. Because the `MetadataPayload` Borsh encoding is identical across all these chains (same prefix byte `0x01`, same fields, same order, no chain discriminator), a single MPC signature is cryptographically valid on every chain simultaneously.

An attacker who observes a legitimate `deployToken` transaction on chain A can:

1. Extract the `(signatureData, MetadataPayload)` from the on-chain calldata.
2. Submit the identical call to `deployToken`/`deploy_token` on chains B, C, D… before the bridge operator does.
3. The token is deployed on those chains without any new MPC authorization.

Concrete consequences:
- **Unauthorized deployer action**: The attacker executes a deployer-equivalent action (token contract creation + bridge registry update) on chains the bridge operator has not yet authorized, bypassing the intended per-chain deployment gating.
- **Permanent registry pre-emption**: Once deployed, the `ERR_TOKEN_EXIST` / `"ERR_TOKEN_EXIST"` guard prevents any subsequent legitimate deployment of the same token on that chain. The bridge operator cannot re-deploy through the normal flow and must resort to admin-only paths.
- **Wormhole notification side-effect** (Wormhole variant): `deployTokenExtension` in `OmniBridgeWormhole.sol` emits a Wormhole message upon deployment. A replayed deployment on an unintended chain emits a Wormhole VAA that NEAR's `wormhole-omni-prover-proxy` may process, registering the token address for that chain on NEAR without operator intent. [8](#0-7) 

---

### Likelihood Explanation

- `deployToken`/`deploy_token` is a **public, permissionless** function on all chains — no role or access control gates the call, only a valid signature.
- The signature and payload are fully visible in on-chain calldata the moment a legitimate deployment is mined on any chain.
- The attacker needs no privileged access, no leaked keys, and no off-chain coordination beyond reading public blockchain state.
- The bridge is live on multiple EVM chains simultaneously (Ethereum, Arbitrum, Base, Polygon, BNB per the README), making cross-chain replay trivially executable.

---

### Recommendation

Include the destination chain ID in the `MetadataPayload` Borsh encoding before hashing, mirroring the pattern already used in `TransferMessagePayload`:

- **EVM**: Add `bytes1(omniBridgeChainId)` to the `borshEncoded` concatenation in `deployToken`.
- **Starknet**: Add `chain_id` parameter to `MetadataPayloadImpl::to_borsh()` and append it, matching `TransferMessagePayloadImpl::to_borsh(chain_id)`.
- **Solana**: Add `writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;` in `DeployTokenPayload::serialize_for_near`, matching `FinalizeTransferPayload::serialize_for_near`.

The NEAR MPC signing path (`sign_transfer` / `MetadataPayload`) must also encode the target chain ID so the signed payload is chain-specific.

---

### Proof of Concept

1. Bridge operator submits `deployToken(sig, {token: "usdc.near", name: "USD Coin", symbol: "USDC", decimals: 6})` on Ethereum (chain ID byte `0x01`). Transaction is mined; `sig` and payload are public.

2. Attacker reads `sig` and payload from Ethereum calldata.

3. Attacker calls `deployToken(sig, {token: "usdc.near", name: "USD Coin", symbol: "USDC", decimals: 6})` on Arbitrum (chain ID byte `0x02`) before the bridge operator does.

4. EVM `deployToken` on Arbitrum computes:
   ```
   keccak256(0x01 || borsh("usdc.near") || borsh("USD Coin") || borsh("USDC") || 0x06)
   ```
   — identical to the Ethereum hash. `ECDSA.recover` returns `nearBridgeDerivedAddress`. Signature accepted.

5. A new `BridgeToken` proxy is deployed on Arbitrum and registered in `nearToEthToken["usdc.near"]`.

6. Bridge operator's subsequent legitimate `deployToken` call on Arbitrum reverts with `ERR_TOKEN_EXIST`.

7. `OmniBridgeWormhole.deployTokenExtension` emits a Wormhole VAA for Arbitrum, which NEAR's prover may process — registering the attacker-triggered token address as the canonical USDC address on Arbitrum in NEAR's bridge state.

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

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L30-35)
```rust
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. recipient
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L48-70)
```text
    function deployTokenExtension(
        string memory token,
        address tokenAddress,
        uint8 decimals,
        uint8 originDecimals
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.DeployToken)),
            Borsh.encodeString(token),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            bytes1(decimals),
            bytes1(originDecimals)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: msg.value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```
