Audit Report

## Title
Cross-Chain Replay of `deploy_token` MPC Signatures Enables Unauthorized Token Deployment on Any Bridge Chain — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

## Summary
The Borsh-encoded payload that the NEAR MPC signs for `deploy_token` / `deployToken` operations contains only `[PayloadType::Metadata, token, name, symbol, decimals]` with no destination chain identifier. Because this encoding is byte-for-byte identical on EVM, Starknet, and Solana, a single NEAR MPC ECDSA signature obtained for one chain is cryptographically valid on every other supported chain. Any observer can extract the signature from the public NEAR event log and call `deployToken` / `deploy_token` on any chain where the token has not yet been deployed, bypassing the bridge operator's chain-specific approval.

## Finding Description

**Root cause — chain ID absent from the `deploy_token` signed payload on all three chains**

**EVM** (`OmniBridge.sol` lines 142–153): `deployToken` constructs the Borsh payload as `[0x01 | token | name | symbol | decimals]` and verifies `ECDSA.recover(keccak256(borshEncoded), signatureData) == nearBridgeDerivedAddress`. No `omniBridgeChainId` is included. [1](#0-0) 

**Starknet** (`bridge_types.cairo` lines 36–44): `MetadataPayload.to_borsh()` encodes `[PayloadType::Metadata(=1), token, name, symbol, decimals]` with no chain ID argument, unlike `TransferMessagePayload.to_borsh(chain_id)` which takes and embeds `chain_id` at lines 61–67. [2](#0-1) [3](#0-2) 

**Solana** (`deploy_token.rs` lines 19–26): `DeployTokenPayload::serialize_for_near` writes `IncomingMessageType::Metadata` then `self.serialize(...)` (token, name, symbol, decimals) — no `SOLANA_OMNI_BRIDGE_CHAIN_ID`. Contrast with `FinalizeTransferPayload::serialize_for_near` (lines 30–35) which writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` before both the token mint and the recipient. [4](#0-3) [5](#0-4) 

**Encoding identity confirmed**: `PayloadType::Metadata` / `IncomingMessageType::Metadata` all serialize to `0x01` on every chain (second variant of a 0-indexed Borsh enum, confirmed by unit test at `near/omni-types/src/tests/lib_test.rs:83–84`). The full layout `[0x01][u32-LE len(token)][token bytes][u32-LE len(name)][name bytes][u32-LE len(symbol)][symbol bytes][decimals u8]` is identical on EVM, Starknet, and Solana for the same NEAR token. [6](#0-5) 

**NEAR signing produces a single chain-agnostic signature**: `log_metadata_callback` constructs `MetadataPayload { prefix: PayloadType::Metadata, token, name, symbol, decimals }`, computes `keccak256(borsh::to_vec(&metadata_payload))`, and submits it to the MPC signer. No chain ID is included. [7](#0-6) 

**Signature is publicly observable**: `sign_log_metadata_callback` emits the MPC signature in a `LogMetadataEvent` log string immediately after signing completes. [8](#0-7) 

**No role gate on `deploy_token`**: All three entry points are permissionless beyond the signature check. EVM has only `whenNotPaused(PAUSED_DEPLOY_TOKEN)`. Starknet has only the pause assertion. Solana has no pause at all (confirmed by `solana/SECURITY.md`: "`deploy_token` … [is] not subject to pause controls"). [9](#0-8) [10](#0-9) [11](#0-10) 

**Exploit path**:
1. Bridge operator calls `log_metadata` on NEAR for token `"usdc.near"`. NEAR MPC signs `keccak256([0x01, 9, "usdc.near", 4, "USDC", 4, "USDC", 6])` and emits the signature `S` in a public `LogMetadataEvent`.
2. Attacker reads `S` from the NEAR event log.
3. Attacker calls `deployToken(S, {token:"usdc.near", name:"USDC", symbol:"USDC", decimals:6})` on any EVM chain where the token is not yet deployed. The Borsh encoding is identical; `ECDSA.recover` returns `nearBridgeDerivedAddress`; the token is deployed and registered in `nearToEthToken`.
4. Attacker repeats on Starknet (`deploy_token`) and Solana (`deploy_token`) using the same `S`.
5. All chains now have `"usdc.near"` registered without the bridge operator approving those specific deployments.

## Impact Explanation

This is an **authorization bypass** matching the allowed critical impact: *"Unauthorized transaction, authorization bypass, role bypass, pause bypass, or signer/prover verification bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."* It also matches: *"Cross-chain replay … or chain/domain separation flaw enabling invalid finalization."*

Concrete consequences:
- `nearToEthToken` / `near_to_starknet_token` / the Solana wrapped-mint PDA are written for a token the operator never approved on that chain.
- If the operator intends different decimal normalization per chain, the attacker forces the first-seen configuration on all chains.
- Once registered, subsequent `finTransfer` calls from NEAR will mint/unlock against the attacker-forced token contracts on chains the bridge infrastructure may not be ready to support, potentially causing permanent loss of bridged funds.

## Likelihood Explanation

The attack requires only: (a) monitoring NEAR events (public, no privilege needed), (b) submitting one transaction per target chain (permissionless). The NEAR MPC signature is emitted immediately after `sign_log_metadata` completes. The replay call is trivially automatable. No victim mistake, no leaked key, no privileged access, and no external dependency is required.

## Recommendation

Include the destination chain ID in the `deploy_token` signed payload, mirroring the pattern already used by `fin_transfer`:

- **EVM**: Add `bytes1(omniBridgeChainId)` to the `borshEncoded` concatenation in `deployToken`.
- **Starknet**: Add a `chain_id: u8` parameter to `MetadataPayload.to_borsh()` and append it after the `PayloadType::Metadata` byte, then pass `self.omni_bridge_chain_id.read()` at the call site in `deploy_token`.
- **Solana**: Write `SOLANA_OMNI_BRIDGE_CHAIN_ID` into the writer before `self.serialize(...)` in `DeployTokenPayload::serialize_for_near`.
- **NEAR**: Update `log_metadata_callback` to include the target chain ID in the `MetadataPayload` before submitting to the MPC signer, so signatures are chain-scoped from creation.

## Proof of Concept

**Minimal reproducible test (local unit test on Solana):**

1. Generate a secp256k1 keypair and configure it as `derived_near_bridge_address` in the Solana config (as done in existing mollusk tests at `solana/programs/bridge_token_factory/tests/mollusk/helpers.rs:418–428`).
2. Construct `DeployTokenPayload { token: "usdc.near".to_string(), name: "USDC".to_string(), symbol: "USDC".to_string(), decimals: 6 }`.
3. Call `serialize_for_near(())` and sign the result with the keypair — this simulates the NEAR MPC signature for chain A.
4. Submit the same `SignedPayload` to the Solana `deploy_token` instruction — it succeeds, creating the wrapped mint PDA.
5. Demonstrate that the identical signature bytes also pass `ECDSA.recover` on EVM (using the EVM test helpers at `evm/tests/helpers/signatures.ts`) and `_verify_borsh_signature` on Starknet (using `starknet/tests/test_contract.cairo:build_deploy_token_message`) — all three accept the same signature, confirming the cross-chain replay. [12](#0-11) [13](#0-12)

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

**File:** near/omni-types/src/tests/lib_test.rs (L80-86)
```rust
fn test_payload_prefix() {
    let res = borsh::to_vec(&PayloadType::TransferMessage).unwrap();
    assert_eq!(hex::encode(res), "00");
    let res = borsh::to_vec(&PayloadType::Metadata).unwrap();
    assert_eq!(hex::encode(res), "01");
    let res = borsh::to_vec(&PayloadType::ClaimNativeFee).unwrap();
    assert_eq!(hex::encode(res), "02");
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

**File:** near/omni-bridge/src/lib.rs (L375-383)
```rust
        if let Ok(signature) = call_result {
            env::log_str(
                &OmniBridgeEvent::LogMetadataEvent {
                    signature,
                    metadata_payload,
                }
                .to_log_string(),
            );
        }
```

**File:** starknet/src/omni_bridge.cairo (L202-205)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L66-76)
```rust
    pub fn deploy_token(
        ctx: Context<DeployToken>,
        data: SignedPayload<DeployTokenPayload>,
    ) -> Result<()> {
        msg!("Deploying token");

        data.verify_signature((), &ctx.accounts.common.config.derived_near_bridge_address)?;
        ctx.accounts.initialize_token_metadata(data.payload)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/tests/mollusk/helpers.rs (L431-441)
```rust
/// Sign serialized payload: keccak256 hash then secp256k1 sign.
/// Returns [r(32) || s(32) || recovery_id(1)] = 65 bytes.
pub fn sign_payload(secret: &libsecp256k1::SecretKey, data: &[u8]) -> [u8; 65] {
    let hash: [u8; 32] = Keccak256::digest(data).into();
    let message = libsecp256k1::Message::parse(&hash);
    let (sig, recid) = libsecp256k1::sign(&message, secret);

    let mut result = [0u8; 65];
    result[..64].copy_from_slice(&sig.serialize());
    result[64] = recid.serialize();
    result
```

**File:** starknet/tests/test_contract.cairo (L82-93)
```text
// Build borsh-encoded message for deploy_token (MetadataPayload)
fn build_deploy_token_message(payload: @MetadataPayload) -> u256 {
    let mut borsh_bytes: ByteArray = "";
    borsh_bytes.append_byte(1); // PayloadType::MetadataPayload
    borsh_bytes.append(@borsh::encode_byte_array(payload.token));
    borsh_bytes.append(@borsh::encode_byte_array(payload.name));
    borsh_bytes.append(@borsh::encode_byte_array(payload.symbol));
    borsh_bytes.append_byte(*payload.decimals);

    let hash_le = compute_keccak_byte_array(@borsh_bytes);
    reverse_u256_bytes(hash_le)
}
```
