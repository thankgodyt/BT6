### Title
Cross-Chain Replay of NEAR MPC `deployToken` Signature Due to Missing Chain Discriminator in Borsh Encoding — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` constructs a Borsh-encoded message for NEAR MPC signature verification that **omits `omniBridgeChainId`**. Because the signed bytes are chain-agnostic, a valid signature obtained for one EVM deployment (e.g., Ethereum) can be replayed verbatim on any other EVM deployment (e.g., Arbitrum) that shares the same `nearBridgeDerivedAddress` — which is the intended production configuration.

---

### Finding Description

In `OmniBridge.deployToken`, the bytes submitted to `ECDSA.recover` are:

```
PayloadType.Metadata | token | name | symbol | decimals
``` [1](#0-0) 

No chain identifier is included. Compare this to `finTransfer`, which correctly embeds `omniBridgeChainId` **twice** in its signed payload: [2](#0-1) 

The `MetadataPayload` struct itself carries no chain field: [3](#0-2) 

In production, all EVM `OmniBridgeWormhole` deployments are initialized with the **same** `nearBridgeDerivedAddress` (the NEAR MPC-derived Ethereum address), because the MPC key is chain-agnostic: [4](#0-3) 

The Starknet implementation has the identical omission in `MetadataPayload.to_borsh()`: [5](#0-4) 

**Attack path:**

1. Observe (or obtain) a valid `(signatureData, MetadataPayload)` pair from a successful `deployToken` call on chain A (Ethereum).
2. Call `deployToken(signatureData, metadata)` on chain B (Arbitrum) with the identical arguments.
3. `ECDSA.recover(keccak256(borshEncoded), signatureData)` returns the same `nearBridgeDerivedAddress` because the encoded bytes are identical — the check passes.
4. The `ERR_TOKEN_EXIST` guard only blocks re-deployment on the **same** chain; it does not prevent deployment on chain B if the token hasn't been deployed there yet.
5. A new `BridgeToken` proxy is deployed on chain B; `isBridgeToken`, `nearToEthToken`, and `ethToNearToken` mappings are populated; `DeployToken` is emitted.
6. `deployTokenExtension` in `OmniBridgeWormhole` publishes a Wormhole message containing `omniBridgeChainId` for chain B, informing NEAR that token X is now live on chain B. [6](#0-5) 

7. NEAR processes the Wormhole VAA and registers the token for chain B. NEAR MPC will now sign `finTransfer` messages destined for chain B for this token.
8. Users (or the attacker) can bridge tokens from NEAR to chain B, minting on the unauthorized token contract. The attacker can also front-run the legitimate deployment on chain B, permanently blocking it via `ERR_TOKEN_EXIST`.

---

### Impact Explanation

- **Chain/domain separation flaw**: A single NEAR MPC signature authorizes token deployment on every EVM chain simultaneously, violating the invariant that a signature must bind to exactly one destination chain.
- **Unauthorized token contract creation**: `isBridgeToken`, `nearToEthToken`, `ethToNearToken` are populated on chain B without NEAR's per-chain authorization.
- **Legitimate deployment blocked**: Once the attacker deploys on chain B, the `ERR_TOKEN_EXIST` guard permanently prevents the legitimate deployment on that chain.
- **Wormhole message injection**: The replayed call causes `OmniBridgeWormhole` to publish a Wormhole message registering the token on chain B, causing NEAR to route real user transfers to the attacker-triggered contract.
- **Minting on unintended chain**: After NEAR registers the token for chain B, NEAR MPC will sign `finTransfer` for chain B, minting tokens on the unauthorized contract. While those tokens are backed by NEAR-locked collateral, the deployment itself was never authorized for chain B, constituting an invalid finalization path.

---

### Likelihood Explanation

- The precondition (shared `nearBridgeDerivedAddress` across EVM deployments) is the **intended production configuration**, not a hypothetical.
- All inputs are public: `signatureData` is visible on-chain from the chain A transaction; `MetadataPayload` fields are calldata.
- No privileged access, key compromise, or validator collusion is required.
- The attack is executable by any EOA with gas.

---

### Recommendation

Include `omniBridgeChainId` in the Borsh-encoded bytes that are signed and verified in `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals),
    bytes1(omniBridgeChainId)   // ← add this
);
```

Apply the same fix to the Starknet `MetadataPayload.to_borsh()` and the Solana `DeployTokenPayload.serialize_for_near()`. [5](#0-4) [7](#0-6) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

// Setup: deploy two OmniBridgeWormhole instances with the same nearBridgeDerivedAddress
// but different omniBridgeChainId values (e.g., 1 for Ethereum, 2 for Arbitrum).

// Step 1: obtain a valid signature for chain A
// (signatureData, metadata) observed from a real deployToken tx on chain A

// Step 2: replay on chain B
address tokenOnChainB = bridgeB.deployToken(signatureData, metadata);

// Assert: call succeeds, token deployed on chain B
assert(bridgeB.isBridgeToken(tokenOnChainB));
assert(
    keccak256(bytes(bridgeB.ethToNearToken(tokenOnChainB))) ==
    keccak256(bytes(metadata.token))
);
// The same signatureData that authorized chain A was accepted on chain B
// because omniBridgeChainId is absent from the signed bytes.
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L72-86)
```text
    function initialize(
        address tokenImplementationAddress_,
        address nearBridgeDerivedAddress_,
        uint8 omniBridgeChainId_
    ) public initializer {
        tokenImplementationAddress = tokenImplementationAddress_;
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
        omniBridgeChainId = omniBridgeChainId_;

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init_unchained();
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(PAUSABLE_ADMIN_ROLE, _msgSender());
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-312)
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
```

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L16-21)
```text
    struct MetadataPayload {
        string token;
        string name;
        string symbol;
        uint8 decimals;
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
