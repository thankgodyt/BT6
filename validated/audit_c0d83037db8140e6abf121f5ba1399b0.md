### Title
Cross-Chain Replay of `deployToken`/`deploy_token` Signatures Due to Missing Chain ID in Message Hash — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/bridge_types.cairo`, `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

The `deployToken`/`deploy_token` message hash on EVM, Starknet, and Solana does not include any chain identifier, while the analogous `finTransfer`/`fin_transfer` message hash explicitly encodes the destination chain ID. Because all bridge deployments share the same `nearBridgeDerivedAddress` (derived from the single NEAR MPC key), a valid `deployToken` signature produced by the NEAR MPC for one chain is cryptographically valid on every other supported chain. An unprivileged attacker who observes a `deployToken` transaction on any chain can replay the signature on every other chain to deploy bridge tokens without a new MPC authorization.

---

### Finding Description

**`finTransfer` (protected):** The EVM `finTransfer` Borsh payload includes `omniBridgeChainId` twice:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
    Borsh.encodeUint64(payload.destinationNonce),
    bytes1(payload.originChain),
    Borsh.encodeUint64(payload.originNonce),
    bytes1(omniBridgeChainId),   // ← chain ID
    Borsh.encodeAddress(payload.tokenAddress),
    Borsh.encodeUint128(payload.amount),
    bytes1(omniBridgeChainId),   // ← chain ID again
    ...
);
``` [1](#0-0) 

**`deployToken` (unprotected):** The EVM `deployToken` Borsh payload contains only the token metadata — no chain ID:

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
``` [2](#0-1) 

The same omission exists on Starknet. `MetadataPayloadImpl::to_borsh` encodes only `PayloadType::Metadata`, token, name, symbol, and decimals — no `omni_bridge_chain_id`: [3](#0-2) 

Contrast with `TransferMessagePayloadImpl::to_borsh`, which passes and encodes `chain_id` twice: [4](#0-3) 

The Starknet CLAUDE.md explicitly documents this protection for `fin_transfer` ("Chain ID binding: Destination chain_id encoded in message hash — prevents cross-chain replay") but the same protection is absent from `deploy_token`.

On Solana, `DeployTokenPayload::serialize_for_near` serializes only the `IncomingMessageType::Metadata` discriminant followed by the raw payload fields — no `SOLANA_OMNI_BRIDGE_CHAIN_ID`: [5](#0-4) 

Contrast with `FinalizeTransferPayload::serialize_for_near`, which writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` twice: [6](#0-5) 

Because the `deployToken` Borsh encoding is identical across all chains, and all chains verify against the same `nearBridgeDerivedAddress` (the single NEAR MPC-derived key), the signature is universally valid.

---

### Impact Explanation

An attacker who replays a `deployToken` signature from chain A onto chain B executes a **token deployer action without MPC authorization**:

- On **EVM chains** (Eth, Base, Arb, Pol, BNB, HyperEvm, Abs): the bridge contract deploys a new `ERC1967Proxy` via `new` (CREATE opcode), whose address is nonce-dependent. The attacker triggers this deployment at the bridge contract's current nonce on chain B, permanently fixing the bridge token address to a value the official system did not intend. The `ERR_TOKEN_EXIST` guard then blocks any subsequent official deployment for that token on chain B. [7](#0-6) 

- On **Starknet**: the token address is deterministic (salt = `keccak(token_id).low`), so the address is the same regardless of caller. However, the attacker still executes an unauthorized `deploy_token` call, setting the `near_to_starknet_token` and `starknet_to_near_token` mappings before the official deployment. [8](#0-7) 

- On **Solana**: the mint PDA is deterministic (`b"wrapped_mint" + hashed_token_id`), but the attacker still triggers unauthorized token registration.

The net result is an **authorization bypass** allowing an unprivileged attacker to execute token deployer actions across all supported chains using a single MPC signature obtained by observing any one chain's `deployToken` transaction.

---

### Likelihood Explanation

All `deployToken` transactions are public on-chain. An attacker needs only to:
1. Monitor any supported chain for a `deployToken` call.
2. Extract the `signatureData` and `metadata` from the calldata.
3. Submit the identical call to every other supported chain before the official relayer does.

No privileged access, leaked keys, or off-chain coordination is required. The attack is executable by any external observer immediately after a `deployToken` transaction is broadcast.

---

### Recommendation

Include the destination chain identifier in the `deployToken`/`deploy_token` Borsh-encoded payload, exactly as `finTransfer`/`fin_transfer` already does. On EVM:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
+   bytes1(omniBridgeChainId),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the equivalent fix to `MetadataPayloadImpl::to_borsh` in `starknet/src/bridge_types.cairo` and `DeployTokenPayload::serialize_for_near` in `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`. The NEAR MPC signing logic must also be updated to include the target chain ID when constructing the payload to sign.

---

### Proof of Concept

1. Observe a `deployToken(signatureData, metadata)` call on Ethereum mainnet for token `"usdc.near"` with name `"USD Coin"`, symbol `"USDC"`, decimals `6`.
2. The Borsh-encoded message is: `[0x01] ++ borsh("usdc.near") ++ borsh("USD Coin") ++ borsh("USDC") ++ [0x06]`. This is identical on every EVM chain, Starknet, and Solana.
3. Submit the same `signatureData` and `metadata` to the Base bridge contract (`0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`) before the official relayer does.
4. `ECDSA.recover(hashed, signatureData)` returns `nearBridgeDerivedAddress` (same key, same hash) → signature accepted.
5. The token is deployed on Base at the bridge contract's current nonce. The `nearToEthToken["usdc.near"]` mapping is set to this address.
6. When the official relayer later attempts to deploy `"usdc.near"` on Base, `require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST")` reverts — the official deployment is permanently blocked.
7. Repeat for Arbitrum, Polygon, Starknet, and Solana using the same signature.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L155-193)
```text
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

**File:** starknet/src/omni_bridge.cairo (L202-240)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);

            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');

            let decimals = _normalizeDecimals(payload.decimals);

            let mut constructor_calldata: Array<felt252> = array![];
            (payload.name.clone(), payload.symbol.clone(), decimals)
                .serialize(ref constructor_calldata);

            // Use the low part of the u256 hash to ensure it fits in felt252
            let salt: felt252 = token_id_hash.low.into();
            let (contract_address, _) = deploy_syscall(
                self.bridge_token_class_hash.read(), salt, constructor_calldata.span(), false,
            )
                .unwrap_syscall();

            self.starknet_to_near_token.write(contract_address, payload.token.clone());
            self.near_to_starknet_token.write(token_id_hash, contract_address);

            self
                .emit(
                    Event::DeployToken(
                        DeployToken {
                            token_address: contract_address,
                            near_token_id: payload.token,
                            name: payload.name,
                            symbol: payload.symbol,
                            decimals,
                            origin_decimals: payload.decimals,
                        },
                    ),
                )
        }
```
