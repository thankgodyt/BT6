### Title
Cross-Chain Replay of `deployToken` Signature Due to Missing Chain ID in Metadata Hash — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/bridge_types.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The `deployToken`/`deploy_token` signature hash across EVM, Starknet, and Solana bridge contracts does not include any chain identifier. Because the same NEAR MPC-derived address (`nearBridgeDerivedAddress`) is used across all destination chains, a single valid NEAR MPC signature for a `MetadataPayload` can be replayed on every other supported chain to deploy bridge tokens without NEAR explicitly authorizing the deployment on each chain. This is the direct analog of the reported EIP-4337 paymaster hash missing `chainId`.

---

### Finding Description

**Root cause — EVM (`OmniBridge.sol` lines 142–149):**

The `deployToken` function constructs the hash as:

```
keccak256(PayloadType.Metadata | token | name | symbol | decimals)
```

No `omniBridgeChainId` is included. [1](#0-0) 

Contrast this with `finTransfer` (lines 289–309), which correctly embeds `omniBridgeChainId` twice in the hash (once for the token address chain, once for the recipient chain), making those signatures chain-specific. [2](#0-1) 

**Root cause — Starknet (`bridge_types.cairo` lines 36–44):**

`MetadataPayloadImpl::to_borsh()` serializes only `PayloadType::Metadata | token | name | symbol | decimals` — no `chain_id` argument is accepted or included. [3](#0-2) 

The `starknet/CLAUDE.md` itself documents "Chain ID binding: Destination chain_id encoded in message hash (not in payload) — prevents cross-chain replay," but this protection exists **only** for `fin_transfer` (which calls `payload.to_borsh(self.omni_bridge_chain_id.read())`), not for `deploy_token` (which calls `payload.to_borsh()` with no argument). [4](#0-3) [5](#0-4) 

**Root cause — Solana (`deploy_token.rs` lines 19–26):**

`DeployTokenPayload::serialize_for_near()` writes only `IncomingMessageType::Metadata` followed by the borsh-encoded struct (token, name, symbol, decimals). No `SOLANA_OMNI_BRIDGE_CHAIN_ID` is written into the signed payload, unlike `FinalizeTransferPayload::serialize_for_near()` which writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` for both the token and recipient fields. [6](#0-5) [7](#0-6) 

**Why replay is possible:**

The `nearBridgeDerivedAddress` verified in `deployToken` on every EVM chain is the same key — it is derived from the NEAR MPC network and is chain-agnostic. A signature over `keccak256(Metadata | token | name | symbol | decimals)` is therefore cryptographically valid on Ethereum, Arbitrum, Base, BNB, Polygon, HyperEVM, and Abstract simultaneously. [8](#0-7) 

---

### Impact Explanation

An attacker who observes a valid `deployToken` transaction on any one EVM chain (e.g., Ethereum) can extract the signature and replay it verbatim on every other EVM chain that runs the same `OmniBridge` contract with the same `nearBridgeDerivedAddress`. The result is:

1. **Unauthorized deployer-equivalent action**: Bridge tokens are deployed on chains for which NEAR never issued a chain-specific authorization. The attacker executes a deployer action on behalf of the NEAR bridge without NEAR's explicit per-chain consent.
2. **Blocking legitimate deployment**: Once the attacker's replayed call succeeds, `nearToEthToken[metadata.token]` is set and `isBridgeToken` is marked. Any subsequent legitimate `deployToken` call for the same NEAR token ID on that chain reverts with `ERR_TOKEN_EXIST`, permanently preventing NEAR from deploying the token through its own authorized flow on that chain.
3. **Forced NEAR registration via proof**: The attacker can then submit a proof of the replayed `DeployToken` event to NEAR's `deploy_token` function. Because the emitter is the registered factory and the proof is cryptographically valid, NEAR's `deploy_token_callback` will register the attacker-triggered token address for that chain — causing NEAR to treat an unauthorized deployment as canonical.

---

### Likelihood Explanation

- All EVM `OmniBridge` deployments share the same `nearBridgeDerivedAddress` (NEAR MPC-derived key).
- Every `deployToken` transaction is public on-chain; the signature is trivially extractable from calldata.
- No special access, private keys, or admin compromise is required — any observer of a `deployToken` transaction on one chain can replay it on all others.
- The bridge is live on Ethereum, Arbitrum, Base, and Polygon simultaneously, making the replay surface immediately available.

---

### Recommendation

Include the destination chain identifier in the `MetadataPayload` hash for all three implementations:

**EVM** — add `omniBridgeChainId` to the `borshEncoded` bytes in `deployToken`:
```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),   // <-- add this
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

**Starknet** — change `MetadataPayloadImpl::to_borsh()` to accept and embed `chain_id: u8`, mirroring `TransferMessagePayloadImpl::to_borsh(chain_id)`.

**Solana** — write `SOLANA_OMNI_BRIDGE_CHAIN_ID` into `DeployTokenPayload::serialize_for_near()` before the token fields, mirroring the pattern already used in `FinalizeTransferPayload`.

The NEAR-side `sign_log_metadata` / `log_metadata` signing path must be updated to include the destination chain ID in the payload it signs, so that the new chain-bound signatures are produced correctly.

---

### Proof of Concept

1. Observe a legitimate `deployToken(signatureData, metadata)` call on Ethereum mainnet (`0xe00c629...`). Extract `signatureData` from the transaction calldata.
2. Call `deployToken(signatureData, metadata)` on Arbitrum's `OmniBridge` (`0xd025b38...`) with the identical arguments.
3. The Arbitrum contract computes `keccak256(Metadata | token | name | symbol | decimals)` — identical to Ethereum's hash — and `ECDSA.recover` returns the same `nearBridgeDerivedAddress`. Signature verification passes.
4. A new `BridgeToken` is deployed on Arbitrum and registered as `isBridgeToken`, without NEAR ever signing a message for Arbitrum.
5. Any subsequent legitimate `deployToken` for the same NEAR token ID on Arbitrum reverts with `ERR_TOKEN_EXIST`. [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** starknet/src/bridge_types.cairo (L34-45)
```text
#[generate_trait]
pub impl MetadataPayloadImpl of MetadataPayloadTrait {
    fn to_borsh(self: @MetadataPayload) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::Metadata.into());
        borsh_bytes.append(@borsh::encode_byte_array(self.token));
        borsh_bytes.append(@borsh::encode_byte_array(self.name));
        borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
        borsh_bytes.append_byte(*self.decimals);
        borsh_bytes
    }
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

**File:** solana/programs/bridge_token_factory/src/state/message/deploy_token.rs (L16-27)
```rust
impl Payload for DeployTokenPayload {
    type AdditionalParams = ();

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

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L20-43)
```rust
    fn serialize_for_near(&self, params: Self::AdditionalParams) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
        // 0. prefix
        IncomingMessageType::InitTransfer.serialize(&mut writer)?;
        // 1. destination_nonce
        self.destination_nonce.serialize(&mut writer)?;
        // 2. transfer_id
        writer.write_all(&[self.transfer_id.origin_chain])?;
        self.transfer_id.origin_nonce.serialize(&mut writer)?;
        // 3. token
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. recipient
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
        // 6. fee_recipient
        self.fee_recipient.serialize(&mut writer)?;

        writer
            .into_inner()
            .map_err(|_| error!(ErrorCode::InvalidArgs))
    }
```
