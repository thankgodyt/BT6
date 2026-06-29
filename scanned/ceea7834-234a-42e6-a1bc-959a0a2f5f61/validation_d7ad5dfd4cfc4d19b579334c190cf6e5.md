### Title
`deployToken` Signature Lacks Chain-ID Binding, Enabling Cross-Chain Replay Across EVM Deployments — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` verifies a NEAR-MPC-produced signature over a Borsh-encoded payload that contains only token metadata (`PayloadType::Metadata | token | name | symbol | decimals`). No EVM chain identifier or contract address is included. Because every EVM-chain OmniBridge deployment shares the same `nearBridgeDerivedAddress` (derived from the same NEAR MPC key), a signature produced for one chain is cryptographically valid on every other EVM chain. An unprivileged attacker can observe a legitimate `deployToken` call on Ethereum and replay the identical `(signatureData, metadata)` arguments on Arbitrum, Base, Polygon, HyperEVM, or Abstract.

---

### Finding Description

`deployToken` constructs its hash as:

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

The payload contains no `omniBridgeChainId`, no `block.chainid`, and no `address(this)`. Compare this to `finTransfer`, which correctly embeds `omniBridgeChainId` twice (for the token address and the recipient address fields):

```solidity
bytes1(omniBridgeChainId),
Borsh.encodeAddress(payload.tokenAddress),
Borsh.encodeUint128(payload.amount),
bytes1(omniBridgeChainId),
Borsh.encodeAddress(payload.recipient),
``` [2](#0-1) 

Because `nearBridgeDerivedAddress` is the same public key across all EVM deployments (it is derived from the NEAR MPC network's shared key), the signature check at line 151 passes identically on every EVM chain for the same `(signatureData, metadata)` tuple.

The same omission exists in the Solana `DeployTokenPayload::serialize_for_near`, which serializes only `IncomingMessageType::Metadata` followed by the token fields, with no `SOLANA_OMNI_BRIDGE_CHAIN_ID` — unlike `FinalizeTransferPayload::serialize_for_near`, which explicitly writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` before both the token mint and the recipient:

```rust
fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
    IncomingMessageType::Metadata.serialize(&mut writer)?;
    self.serialize(&mut writer)?; // no chain id
    ...
}
``` [3](#0-2) 

```rust
writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
params.0.serialize(&mut writer)?; // mint
...
writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
params.1.serialize(&mut writer)?; // recipient
``` [4](#0-3) 

---

### Impact Explanation

An attacker who observes a valid `deployToken(signatureData, metadata)` call on any one EVM chain can immediately submit the identical call on every other EVM OmniBridge deployment. Each target contract will:

1. Accept the signature (same `nearBridgeDerivedAddress`, same hash).
2. Deploy a new `BridgeToken` proxy for the NEAR token ID.
3. Write `isBridgeToken[proxy] = true`, `ethToNearToken[proxy] = metadata.token`, `nearToEthToken[metadata.token] = proxy`.

This constitutes an **authorization bypass for a deployer action**: the NEAR MPC signed a metadata payload authorizing deployment on one specific chain; the attacker uses that authorization to execute the same deployer action on every other EVM chain without any additional MPC approval. Once the mapping `nearToEthToken[metadata.token]` is set on a chain, the NEAR bridge cannot later perform a legitimate deployment for that token on that chain (the `ERR_TOKEN_EXIST` guard fires), permanently locking the bridge into using the attacker-triggered deployment or being unable to serve that token on that chain at all. [5](#0-4) 

---

### Likelihood Explanation

All `deployToken` calls are public on-chain transactions. Any observer of the Ethereum mempool or block history can extract `signatureData` and `metadata` and immediately replay them on Arbitrum, Base, Polygon, HyperEVM, or Abstract. No privileged access, leaked keys, or social engineering is required. The only precondition is that the target token has not yet been deployed on the target chain, which is the normal state before the bridge officially expands to a new chain.

---

### Recommendation

Include `omniBridgeChainId` in the Borsh-encoded payload for `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
+   bytes1(omniBridgeChainId),          // bind to this chain
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the equivalent fix to `DeployTokenPayload::serialize_for_near` on Solana by prepending `SOLANA_OMNI_BRIDGE_CHAIN_ID`, and to the Starknet `deploy_token` borsh encoding by prepending `omni_bridge_chain_id`.

---

### Proof of Concept

1. NEAR bridge signs a `MetadataPayload` for token `"usdc.near"` (name `"USD Coin"`, symbol `"USDC"`, decimals `6`) to be deployed on Ethereum (`omniBridgeChainId = 1`). The MPC produces `signatureData`.
2. A relayer calls `OmniBridge(Ethereum).deployToken(signatureData, metadata)`. The token is deployed on Ethereum. The call succeeds.
3. An attacker copies `signatureData` and `metadata` from the Ethereum transaction.
4. The attacker calls `OmniBridge(Arbitrum).deployToken(signatureData, metadata)`. The Borsh encoding is identical (no chain ID in the payload). `ECDSA.recover(keccak256(borshEncoded), signatureData)` returns the same `nearBridgeDerivedAddress`. The check passes. A new `BridgeToken` is deployed on Arbitrum and registered in `nearToEthToken["usdc.near"]`.
5. When the NEAR bridge later attempts to officially deploy USDC on Arbitrum, the call reverts with `ERR_TOKEN_EXIST`, permanently blocking the legitimate deployment path for that token on Arbitrum. [6](#0-5)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L155-158)
```text
        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L294-298)
```text
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
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
