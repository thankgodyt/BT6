### Title
Cross-Chain Replay of `deployToken` / `deploy_token` Signatures via Missing Chain-ID Binding — (`near/omni-bridge/src/lib.rs`, `evm/src/omni-bridge/contracts/OmniBridge.sol`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`, `starknet/src/omni_bridge.cairo`)

### Summary

The NEAR MPC signs a `MetadataPayload` that contains no destination chain identifier. Because the signed hash is chain-agnostic, a single valid signature produced for deploying a token on one chain (e.g., Ethereum) can be replayed verbatim on every other supported chain (Arbitrum, Polygon, BNB, Solana, Starknet) by any unprivileged observer. This is the direct analog of H-03: the "identity" (destination chain) is absent from the signed message, so the signer's authorization for one target is silently reused against all other targets.

### Finding Description

**Root cause — NEAR side (`log_metadata_callback`):**

The NEAR bridge constructs and signs a `MetadataPayload` that contains only `prefix`, `token`, `name`, `symbol`, and `decimals`. No chain identifier is included. [1](#0-0) [2](#0-1) 

The resulting 32-byte keccak hash is sent to the MPC signer with a fixed `path` and `key_version`, producing one ECDSA signature that is identical regardless of which chain will receive the `deployToken` call.

**Verification on each chain — no chain binding:**

*EVM (`OmniBridge.sol` `deployToken`):* The hash covers only `PayloadType.Metadata | token | name | symbol | decimals`. `omniBridgeChainId` is **not** included. [3](#0-2) 

*Solana (`deploy_token.rs` `DeployTokenPayload::serialize_for_near`):* The serialized bytes are `IncomingMessageType::Metadata | token | name | symbol | decimals`. `SOLANA_OMNI_BRIDGE_CHAIN_ID` is **not** included. [4](#0-3) 

*Starknet (`omni_bridge.cairo` `deploy_token`):* `payload.to_borsh()` is called with no `chain_id` argument. `MetadataPayloadImpl::to_borsh` encodes only `PayloadType::Metadata | token | name | symbol | decimals`. [5](#0-4) [6](#0-5) 

**Contrast with `finTransfer` (correctly protected):**

For token transfers, every chain embeds its own chain ID in the signed hash (`omniBridgeChainId` on EVM, `SOLANA_OMNI_BRIDGE_CHAIN_ID` on Solana, `omni_bridge_chain_id` on Starknet), preventing cross-chain replay. The `deployToken` path has no equivalent protection. [7](#0-6) [8](#0-7) 

### Impact Explanation

An attacker who observes a valid `deployToken` transaction on any chain can immediately replay the same `(signatureData, MetadataPayload)` tuple on every other chain where the bridge is deployed. Each target chain's bridge contract will:

1. Accept the signature as valid (it recovers to `nearBridgeDerivedAddress`).
2. Deploy a new token contract and register it in its own `nearToEthToken` / `wrapped_mint` / `near_to_starknet_token` mapping.

Consequences:
- **Unauthorized token deployment** on chains the NEAR side has not yet authorized, constituting a signer/prover verification bypass and token-deployer action executed without per-chain authorization.
- **Bridge state desynchronization**: the NEAR hub has not registered the token for the replayed chain. If users subsequently call `initTransfer` on that chain (burning/locking real tokens), the NEAR side will reject the inbound proof because the token is unknown for that source chain, resulting in permanent loss of the burned/locked tokens.
- **Blocking legitimate deployment**: once the token is registered via replay, the legitimate `deployToken` call for that chain will revert (`ERR_TOKEN_EXIST` / `ERR_TOKEN_ALREADY_DEPLOYED` / PDA collision), permanently preventing the NEAR-authorized deployment from succeeding.

### Likelihood Explanation

The attack requires only:
1. Watching any public chain for a `deployToken` transaction (zero privilege).
2. Submitting the same calldata to the bridge contract on any other chain.

No private keys, no admin access, no MEV infrastructure. Any token deployment on any chain is immediately replayable on all others. The attack is trivially automatable.

### Recommendation

Include the destination chain identifier in the `MetadataPayload` before it is hashed and signed by the MPC, mirroring the existing protection on `TransferMessagePayload`:

- **NEAR side**: add a `destination_chain: ChainKind` field to `MetadataPayload` and include it in the borsh-serialized bytes passed to `keccak256_array` before calling `sign`.
- **EVM**: include `bytes1(omniBridgeChainId)` in the `borshEncoded` bytes inside `deployToken`.
- **Solana**: include `SOLANA_OMNI_BRIDGE_CHAIN_ID` in `DeployTokenPayload::serialize_for_near`.
- **Starknet**: pass `self.omni_bridge_chain_id.read()` into `MetadataPayloadImpl::to_borsh` and append it to the serialized bytes, exactly as `TransferMessagePayloadImpl::to_borsh` already does.

### Proof of Concept

1. Alice (legitimate relayer) calls `deployToken(sig, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` on Ethereum. Transaction is public.
2. Attacker copies `sig` and the payload verbatim and calls `deployToken(sig, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` on Arbitrum, Polygon, BNB, Starknet, and Solana.
3. Each chain's bridge accepts the signature (it recovers to `nearBridgeDerivedAddress`) and deploys a `usdc.near` token contract, registering it in the local mapping.
4. The NEAR hub has not yet registered `usdc.near` for Arbitrum. A user on Arbitrum calls `initTransfer` for the newly deployed token, burning 1000 USDC. The NEAR side's prover validates the event but `fin_transfer` on NEAR rejects it because `usdc.near` is not mapped to any Arbitrum address in NEAR state. The 1000 USDC are permanently lost.
5. When the legitimate relayer later tries to deploy `usdc.near` on Arbitrum via the normal flow, the call reverts with `ERR_TOKEN_EXIST`, permanently blocking the authorized deployment.

### Citations

**File:** near/omni-bridge/src/lib.rs (L341-360)
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

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
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

**File:** starknet/src/omni_bridge.cairo (L202-205)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
```

**File:** starknet/CLAUDE.md (L45-45)
```markdown
1. **Chain ID binding**: Destination chain_id encoded in message hash (not in payload) - prevents cross-chain replay
```
