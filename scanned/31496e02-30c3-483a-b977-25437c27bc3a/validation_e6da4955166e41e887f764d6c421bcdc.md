### Title
Cross-Chain Replay of `deployToken` Signatures Across EVM Chains Due to Missing Chain ID Binding — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` does not include `omniBridgeChainId` in the Borsh-encoded message that is signed by the NEAR MPC. Because the same `nearBridgeDerivedAddress` is used across all EVM deployments, a valid `deployToken` signature produced for one EVM chain (e.g., Ethereum) can be replayed verbatim on any other EVM chain (e.g., Base, Arbitrum, Polygon) to deploy an unauthorized bridge token. This is a chain/domain separation flaw. By contrast, `finTransfer` on the same contract correctly embeds `omniBridgeChainId` twice in the signed payload, preventing replay there.

---

### Finding Description

`OmniBridge.initialize()` accepts `omniBridgeChainId_` as a deployer-supplied parameter and stores it in storage. [1](#0-0) 

`finTransfer` correctly embeds `omniBridgeChainId` in the Borsh-encoded hash at two positions (destination chain for token address and for recipient): [2](#0-1) 

`deployToken`, however, builds its Borsh-encoded hash from only `PayloadType`, `token`, `name`, `symbol`, and `decimals` — **no chain ID is included**: [3](#0-2) 

The only replay guard in `deployToken` is a per-chain check that the token has not already been deployed on *that* chain: [4](#0-3) 

This guard does not prevent the same signature from being submitted to a *different* chain where the token has not yet been deployed.

The same flaw exists in the Starknet contract. `fin_transfer` passes `self.omni_bridge_chain_id.read()` into `to_borsh()`, but `deploy_token` calls `payload.to_borsh()` with no chain ID argument: [5](#0-4) 

`MetadataPayloadImpl::to_borsh()` encodes only `PayloadType::Metadata`, token, name, symbol, and decimals: [6](#0-5) 

The Starknet CLAUDE.md explicitly documents chain ID binding as a security property for `fin_transfer` but makes no such claim for `deploy_token`: [7](#0-6) 

The Solana `DeployTokenPayload::serialize_for_near()` similarly omits any chain ID from the signed bytes: [8](#0-7) 

---

### Impact Explanation

All EVM deployments share the same `nearBridgeDerivedAddress` (the NEAR MPC-derived Ethereum address). A `deployToken` signature is therefore valid on every EVM chain simultaneously. An attacker who observes a legitimate `deployToken` call on Ethereum can replay the identical `(signatureData, metadata)` tuple on Base, Arbitrum, Polygon, HyperEVM, or Abstract before the legitimate relayer does so. The replayed call succeeds because:

- The signature recovers to `nearBridgeDerivedAddress` (chain ID is absent from the hash).
- The per-chain guard `!isBridgeToken[nearToEthToken[metadata.token]]` passes because the token has not yet been deployed on the target chain.

The deployed bridge token on the target chain is a fully functional `BridgeToken` proxy with the bridge as its mint authority. The NEAR side may subsequently process `initTransfer` events originating from that chain for the replayed token, minting NEAR-side supply that was never authorized for that chain. This constitutes a chain/domain separation flaw enabling unauthorized token deployment and potentially unauthorized cross-chain minting.

---

### Likelihood Explanation

The attack requires no privileged access. Any party who can observe a pending or confirmed `deployToken` transaction on one EVM chain (e.g., from the mempool or block explorer) can immediately replay it on any other supported EVM chain. The Omni Bridge is deployed on at least six EVM chains (Ethereum, Base, Arbitrum, Polygon, HyperEVM, Abstract), all sharing the same `nearBridgeDerivedAddress`. The window for replay exists whenever a new token is being deployed for the first time on a secondary chain.

---

### Recommendation

Include `omniBridgeChainId` in the Borsh-encoded payload that is signed by the NEAR MPC for `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // add chain binding
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the equivalent fix to `MetadataPayloadImpl::to_borsh()` in `starknet/src/bridge_types.cairo` and to `DeployTokenPayload::serialize_for_near()` in `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`. The NEAR MPC signing service must also be updated to include the destination chain ID when producing `deployToken` signatures.

---

### Proof of Concept

1. NEAR MPC produces a valid `deployToken` signature `σ` for token `wrap.near` on Ethereum (`omniBridgeChainId = 1`). The signed hash is `keccak256(borsh(Metadata || "wrap.near" || "Wrapped NEAR" || "wNEAR" || 24))`.
2. Relayer submits `(σ, payload)` to `OmniBridge.deployToken()` on Ethereum. Token is deployed at address `T_eth`.
3. Attacker extracts `(σ, payload)` from the Ethereum transaction.
4. Attacker calls `OmniBridge.deployToken(σ, payload)` on Base (`omniBridgeChainId = 2`). The contract computes the identical hash (no chain ID in the encoding), `ECDSA.recover` returns `nearBridgeDerivedAddress`, the guard `!isBridgeToken[nearToEthToken["wrap.near"]]` passes (token not yet on Base), and a new `BridgeToken` proxy `T_base` is deployed and registered as a valid bridge token.
5. `T_base` is now a fully authorized bridge token on Base, deployed without any NEAR-side authorization for Base. [9](#0-8) [10](#0-9)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L72-79)
```text
    function initialize(
        address tokenImplementationAddress_,
        address nearBridgeDerivedAddress_,
        uint8 omniBridgeChainId_
    ) public initializer {
        tokenImplementationAddress = tokenImplementationAddress_;
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
        omniBridgeChainId = omniBridgeChainId_;
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-313)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

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

**File:** starknet/src/omni_bridge.cairo (L202-205)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
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

**File:** starknet/CLAUDE.md (L44-46)
```markdown
### Design Decisions
1. **Chain ID binding**: Destination chain_id encoded in message hash (not in payload) - prevents cross-chain replay
2. **Public `log_metadata`**: Intentionally permissionless for token discovery
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
