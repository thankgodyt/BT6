### Title
Cross-Chain Replay of `deployToken` Signed Message Across EVM Chains — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` verifies a NEAR-MPC-signed message that does **not** include any chain-binding field (chain ID or contract address). Because the same `nearBridgeDerivedAddress` is derived from the same NEAR MPC key and is shared across every EVM deployment of the bridge (Ethereum, Base, Arbitrum, BNB, Polygon, etc.), a valid `deployToken` signature produced for one EVM chain can be replayed verbatim on any other EVM chain. The same structural flaw exists in the Solana `deploy_token` path.

---

### Finding Description

**EVM — `OmniBridge.sol` `deployToken`**

The signed message is constructed as:

```
PayloadType.Metadata || token || name || symbol || decimals
``` [1](#0-0) 

No `omniBridgeChainId` or contract address is included. Contrast this with `finTransfer`, which explicitly encodes `omniBridgeChainId` **twice** in the signed payload (once for the token address field and once for the recipient field), binding the signature to a specific chain: [2](#0-1) 

**Solana — `deploy_token.rs` `DeployTokenPayload::serialize_for_near`**

The Solana serialization for the incoming `deploy_token` message is:

```
IncomingMessageType::Metadata || token || name || symbol || decimals
``` [3](#0-2) 

No `SOLANA_OMNI_BRIDGE_CHAIN_ID` is written. Compare with `FinalizeTransferPayload::serialize_for_near`, which writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` at both the token and recipient positions: [4](#0-3) 

**Starknet — `omni_bridge.cairo` `deploy_token`**

The test helper `build_deploy_token_message` (which mirrors the on-chain encoding) shows the same omission — no chain ID byte — while `build_fin_transfer_message` includes `chain_id`: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

When NEAR MPC signs a `deployToken` payload for chain A, the signature covers only `{PayloadType, token, name, symbol, decimals}`. An attacker who observes this on-chain transaction can immediately submit the identical `(signatureData, metadata)` tuple to the `deployToken` function on chain B (and every other EVM chain).

On chain B this succeeds because:
1. `ECDSA.recover(hashed, signatureData) == nearBridgeDerivedAddress` — the same MPC-derived key is used on all EVM chains.
2. `isBridgeToken[nearToEthToken[metadata.token]]` is `false` — the token has not yet been deployed there.

After the replay:
- `isBridgeToken`, `nearToEthToken`, and `ethToNearToken` are set on chain B for a token address that NEAR never registered.
- When NEAR later attempts to legitimately deploy the same token on chain B, the call reverts with `ERR_TOKEN_EXIST`.
- NEAR can never register the correct token address for chain B, **permanently blocking all bridging of that token to chain B**.
- Users who lock tokens on NEAR intending to bridge to chain B will have their funds permanently frozen.

---

### Likelihood Explanation

The attack requires no special privilege. Any observer of a public EVM transaction can extract `signatureData` and `metadata` from a confirmed `deployToken` call on chain A and replay it on chain B in the same block or any subsequent block. The attacker needs only a funded wallet on chain B to pay gas. The bridge supports multiple EVM chains (Ethereum, Base, Arbitrum, BNB, Polygon) all sharing the same `nearBridgeDerivedAddress`, so the replay surface is wide.

---

### Recommendation

Include the destination chain ID in the signed message for `deployToken`, mirroring the pattern already used in `finTransfer`. For EVM:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // ADD THIS
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the equivalent fix in the Solana `DeployTokenPayload::serialize_for_near` (write `SOLANA_OMNI_BRIDGE_CHAIN_ID` before the token fields) and in the Starknet `deploy_token` borsh encoding. The NEAR signing side must include the target chain ID in the payload it submits to MPC so the signatures are chain-scoped.

---

### Proof of Concept

1. NEAR MPC signs a `deployToken` message for Ethereum (chain A). A relayer submits it; the transaction is confirmed and publicly visible.

2. Attacker extracts `signatureData` and `metadata` from the Ethereum transaction.

3. Attacker calls `deployToken(signatureData, metadata)` on the Base `OmniBridge` contract (chain B).

4. Verification passes: `ECDSA.recover(keccak256(borshEncoded), signatureData) == nearBridgeDerivedAddress` ✓ (same key, same payload bytes, no chain ID in hash).

5. `isBridgeToken[nearToEthToken[metadata.token]]` is `false` on Base ✓.

6. A new `ERC1967Proxy` is deployed on Base; `isBridgeToken`, `nearToEthToken`, `ethToNearToken` are set.

7. NEAR later attempts to deploy the same token on Base via the normal flow. The call reverts: `"ERR_TOKEN_EXIST"`.

8. The token is permanently undeployable on Base through the legitimate path; any user who bridges that token targeting Base has their funds frozen. [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-195)
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

        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
        uint8 decimals = _normalizeDecimals(metadata.decimals);

        // slither-disable-next-line reentrancy-no-eth
        address bridgeTokenProxy = address(
            new ERC1967Proxy(
                tokenImplementationAddress,
                abi.encodeWithSelector(
                    BridgeToken.initialize.selector,
                    metadata.name,
                    metadata.symbol,
                    decimals
                )
            )
        );

        deployTokenExtension(
            metadata.token,
            bridgeTokenProxy,
            decimals,
            metadata.decimals
        );

        emit BridgeTypes.DeployToken(
            bridgeTokenProxy,
            metadata.token,
            metadata.name,
            metadata.symbol,
            decimals,
            metadata.decimals
        );

        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);

        return bridgeTokenProxy;
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

**File:** starknet/tests/test_contract.cairo (L96-120)
```text
fn build_fin_transfer_message(payload: @TransferMessagePayload, chain_id: u8) -> u256 {
    let mut borsh_bytes: ByteArray = "";
    borsh_bytes.append_byte(0); // PayloadType::TransferMessage
    borsh_bytes.append(@borsh::encode_u64(*payload.destination_nonce));
    borsh_bytes.append_byte(*payload.origin_chain);
    borsh_bytes.append(@borsh::encode_u64(*payload.origin_nonce));
    borsh_bytes.append_byte(chain_id);
    borsh_bytes.append(@borsh::encode_address(*payload.token_address));
    borsh_bytes.append(@borsh::encode_u128(*payload.amount));
    borsh_bytes.append_byte(chain_id);
    borsh_bytes.append(@borsh::encode_address(*payload.recipient));
    match payload.fee_recipient {
        Option::None => { borsh_bytes.append_byte(0); },
        Option::Some(fee_recipient) => {
            borsh_bytes.append_byte(1);
            borsh_bytes.append(@borsh::encode_byte_array(fee_recipient));
        },
    }
    match payload.message {
        Option::None => {},
        Option::Some(message) => { borsh_bytes.append(@borsh::encode_byte_array(message)); },
    }

    let hash_le = compute_keccak_byte_array(@borsh_bytes);
    reverse_u256_bytes(hash_le)
```
