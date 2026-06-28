### Title
Cross-Chain Signature Replay on `deploy_token` / `deployToken` Due to Missing Chain ID in `MetadataPayload` Signing — (`near/omni-bridge/src/lib.rs`, `evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The `MetadataPayload` signed by the NEAR MPC signer for the `deploy_token` / `deployToken` operation does not include any chain identifier. A valid signature obtained on one chain (e.g., Ethereum) can be replayed verbatim on any other supported chain (Starknet, Solana, another EVM chain) to deploy a bridge token without explicit per-chain authorization from the bridge operator. This is in direct contrast to `fin_transfer` / `finTransfer`, which correctly embeds the destination chain ID in its signed payload.

---

### Finding Description

**Root cause — NEAR signing side (`near/omni-bridge/src/lib.rs`):**

In `log_metadata_callback`, the NEAR bridge constructs a `MetadataPayload` and requests an MPC signature over `keccak256(borsh(MetadataPayload))`:

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

The `MetadataPayload` struct contains only `{prefix, token, name, symbol, decimals}` — **no chain ID, no contract address, no nonce**: [2](#0-1) 

**Verification on EVM (`evm/src/omni-bridge/contracts/OmniBridge.sol`):**

`deployToken` reconstructs the same chain-agnostic borsh blob and verifies the signature:

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
``` [3](#0-2) 

No `omniBridgeChainId` is included — unlike `finTransfer`, which explicitly encodes `bytes1(omniBridgeChainId)` twice in its payload. [4](#0-3) 

**Verification on Starknet (`starknet/src/bridge_types.cairo`):**

`MetadataPayloadTrait::to_borsh()` encodes only `{PayloadType::Metadata, token, name, symbol, decimals}`:

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
``` [5](#0-4) 

Contrast with `TransferMessagePayloadTrait::to_borsh(chain_id)`, which correctly embeds `chain_id` twice: [6](#0-5) 

`deploy_token` in Starknet calls `_verify_borsh_signature(ref self, @payload.to_borsh(), signature)` — no chain ID argument: [7](#0-6) 

While `fin_transfer` passes `self.omni_bridge_chain_id.read()`: [8](#0-7) 

**Verification on Solana (`solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`):**

`DeployTokenPayload::serialize_for_near()` serializes only `IncomingMessageType::Metadata` + the payload fields — no `SOLANA_OMNI_BRIDGE_CHAIN_ID`: [9](#0-8) 

Contrast with `FinalizeTransferPayload::serialize_for_near()`, which writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` for both the token and recipient fields: [10](#0-9) 

---

### Impact Explanation

A single MPC-signed `MetadataPayload` for token `X` on Ethereum is byte-for-byte identical to what Starknet, Solana, or any other EVM chain would accept for the same token. An attacker who observes the signature in calldata on Ethereum can immediately submit it to the Starknet or Solana bridge contracts to deploy the same bridge token there — without the bridge operator having authorized that chain for that token.

Concrete consequences:
1. **Unauthorized token deployment**: The attacker deploys a bridge token on a chain where the operator has not yet set up the corresponding infrastructure (relayers, liquidity, etc.).
2. **Permanent registration conflict**: Once deployed, the token is registered in the bridge's token mapping (`near_to_starknet_token`, `nearToEthToken`). A subsequent legitimate deployment attempt by the operator will revert with `ERR_TOKEN_ALREADY_DEPLOYED` / `ERR_TOKEN_EXIST`, permanently blocking the operator's intended deployment flow.
3. **User fund loss**: Users who observe the `DeployToken` event and interact with the prematurely deployed token (e.g., by calling `init_transfer` on Starknet) will lock funds in a bridge that has no authorized relayer or NEAR-side counterpart configured for that chain, resulting in stuck or lost funds. [11](#0-10) 

---

### Likelihood Explanation

The attack requires no special privilege. The `deployToken` / `deploy_token` signature is submitted as public calldata on the source chain and is trivially extractable by any on-chain observer. The attacker only needs to:
1. Watch for a `DeployToken` event on any supported chain.
2. Extract the `signatureData` / `signature` from the transaction calldata.
3. Replay it on any other supported chain with the same `MetadataPayload`.

The bridge is live across Ethereum, Arbitrum, Base, Polygon, Starknet, and Solana simultaneously, making cross-chain replay straightforward. [12](#0-11) 

---

### Recommendation

Include the destination chain ID in the `MetadataPayload` before signing, mirroring the pattern already used for `TransferMessagePayload`:

1. **NEAR side**: Add a `chain_id: ChainKind` field to `MetadataPayload` (or pass it as a parameter to `log_metadata_callback`) and include it in the borsh-serialized bytes before calling `keccak256`.
2. **EVM side**: Include `bytes1(omniBridgeChainId)` in the `borshEncoded` blob inside `deployToken`.
3. **Starknet side**: Change `MetadataPayloadTrait::to_borsh()` to accept a `chain_id: u8` parameter and append it, matching `TransferMessagePayloadTrait::to_borsh(chain_id)`.
4. **Solana side**: Write `SOLANA_OMNI_BRIDGE_CHAIN_ID` into the serialized bytes inside `DeployTokenPayload::serialize_for_near()`, matching `FinalizeTransferPayload::serialize_for_near()`.

---

### Proof of Concept

1. Operator calls `log_metadata("token.near")` on the NEAR bridge. MPC signs `keccak256(borsh({Metadata, "token.near", "Token", "TKN", 18}))` → `sig`.
2. Relayer submits `deployToken(sig, {token: "token.near", name: "Token", symbol: "TKN", decimals: 18})` on Ethereum. Token deployed at `addr_eth`. Signature `sig` is now public in Ethereum calldata.
3. Attacker extracts `sig` from Ethereum calldata.
4. Attacker calls `deploy_token(sig, MetadataPayload{token: "token.near", name: "Token", symbol: "TKN", decimals: 18})` on the Starknet bridge. The Starknet bridge computes `keccak256(borsh({Metadata, "token.near", "Token", "TKN", 18}))` — identical hash — and `verify_eth_signature` passes. Token is deployed on Starknet without operator authorization.
5. When the operator later tries to deploy the token on Starknet, the call reverts with `ERR_TOKEN_ALREADY_DEPLOYED`. [13](#0-12) [14](#0-13)

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

**File:** starknet/src/bridge_types.cairo (L61-84)
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
        match self.fee_recipient {
            Option::None => { borsh_bytes.append_byte(0); },
            Option::Some(fee_recipient) => {
                borsh_bytes.append_byte(1);
                borsh_bytes.append(@borsh::encode_byte_array(fee_recipient));
            },
        }
        match self.message {
            Option::None => {},
            Option::Some(message) => { borsh_bytes.append(@borsh::encode_byte_array(message)); },
        }
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

**File:** near/CLAUDE.md (L1-3)
```markdown
## Overview

NEAR smart contracts for the Omni Bridge - a multi-chain asset bridge enabling trustless cross-chain token transfers. Uses Chain Signatures (MPC) for outbound transfers and light clients/Wormhole for inbound proof verification. Supports multiple blockchain networks including some EVM-compatible chains (such as Ethereum, Arbitrum, Base, etc.), Solana, and some UTXO chains (such as Bitcoin, Zcash, etc.). See `ChainKind` enum in omni-types for full list.
```
