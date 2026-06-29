Audit Report

## Title
Missing Chain ID in `deployToken` Signature Enables Cross-Chain Replay Across EVM Deployments — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
The `deployToken` function in `OmniBridge.sol` verifies a NEAR MPC signature over a borsh-encoded hash that omits `omniBridgeChainId`. Because the MPC signing path `bridge-1` is chain-agnostic, the derived `nearBridgeDerivedAddress` is identical across all EVM deployments (Ethereum, Arbitrum, Base, BNB, etc.). A valid `deployToken` signature observed on one EVM chain can be replayed verbatim on any other EVM chain, deploying a bridge token and emitting a Wormhole VAA to NEAR without chain-specific authorization. This constitutes a chain/domain separation flaw and an authorization bypass enabling deployer-equivalent actions.

## Finding Description
`OmniBridge.sol::deployToken` constructs its signed hash as:

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

No `omniBridgeChainId` is included. By contrast, `finTransfer` encodes `omniBridgeChainId` twice in its hash: [2](#0-1) 

The NEAR MPC signing path is the constant `"bridge-1"`, which is chain-agnostic: [3](#0-2) 

Because MPC key derivation is deterministic per path, the resulting `nearBridgeDerivedAddress` is identical across all EVM deployments. The `MetadataPayload` struct itself contains no chain identifier: [4](#0-3) 

The Starknet `deploy_token` has the same gap — `payload.to_borsh()` is called without `chain_id`: [5](#0-4) 

While `fin_transfer` correctly passes `self.omni_bridge_chain_id.read()`: [6](#0-5) 

And `MetadataPayloadTrait::to_borsh` on Starknet also omits chain ID: [7](#0-6) 

**Exploit flow:**
1. Attacker observes a confirmed `deployToken(signatureData, metadata)` transaction on Ethereum (fully public).
2. Attacker submits the identical calldata to the Arbitrum `OmniBridgeWormhole` contract.
3. Arbitrum computes the same `keccak256(borshEncoded)` (no chain ID), recovers the same `nearBridgeDerivedAddress`, and accepts the signature.
4. The `ERR_TOKEN_EXIST` guard passes because `nearToEthToken[metadata.token]` is zero on Arbitrum: [8](#0-7) 
5. A `BridgeToken` proxy is deployed; `isBridgeToken` and `nearToEthToken` mappings are set: [9](#0-8) 
6. `OmniBridgeWormhole::deployTokenExtension` publishes a Wormhole VAA to NEAR containing `omniBridgeChainId` (Arbitrum's ID) and the attacker-triggered proxy address: [10](#0-9) 
7. NEAR processes the VAA and registers the token for Arbitrum. Any subsequent legitimate `deployToken` for the same `metadata.token` on Arbitrum reverts with `ERR_TOKEN_EXIST`, permanently blocking the authorized deployment.

## Impact Explanation
This is a **Critical** chain/domain separation flaw and authorization bypass. An unprivileged external attacker can execute deployer-equivalent actions — deploying bridge tokens on EVM chains without chain-specific NEAR authorization — and permanently block legitimate authorized deployments via `ERR_TOKEN_EXIST`. The Wormhole VAA emitted causes NEAR to register the unauthorized token for the target chain, enabling `finTransfer` flows to a token contract that NEAR operators never authorized for that chain. This matches the allowed critical impact: *"Cross-chain replay... or chain/domain separation flaw enabling invalid finalization"* and *"Unauthorized transaction, authorization bypass... that lets an attacker execute bridge, token, deployer... admin-equivalent actions."*

## Likelihood Explanation
Exploitation requires only reading a confirmed `deployToken` transaction from any public block explorer and resubmitting the same calldata to a different EVM chain's bridge contract. No privileged access, no private keys, no MEV infrastructure is needed. The only precondition is that the target chain's bridge contract is live and unpaused. Any public observer can perform this immediately after a legitimate deployment on any EVM chain.

## Recommendation
Include `omniBridgeChainId` in the borsh-encoded payload verified in `deployToken`, mirroring the pattern already used in `finTransfer`:

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

Apply the same fix to Starknet's `MetadataPayloadTrait::to_borsh` — add a `chain_id: u8` parameter and embed it, as `TransferMessagePayloadTrait::to_borsh` already does. Update the NEAR MPC signing path to include the destination chain ID in `MetadataPayload` before hashing, so each chain's deployment signature is cryptographically distinct.

## Proof of Concept
1. Deploy `OmniBridgeWormhole` on a local fork of Ethereum and Arbitrum, both initialized with the same `nearBridgeDerivedAddress` (derived from MPC path `bridge-1`).
2. Call `deployToken(sig, metadata)` on the Ethereum fork with a valid NEAR MPC signature; record the calldata.
3. Submit the identical calldata to the Arbitrum fork's `deployToken`.
4. Observe: signature verification passes, a `BridgeToken` proxy is deployed, `isBridgeToken` and `nearToEthToken` are set, and a Wormhole VAA is emitted with Arbitrum's `omniBridgeChainId`.
5. Attempt a legitimate `deployToken` for the same `metadata.token` on the Arbitrum fork; observe revert with `ERR_TOKEN_EXIST`.
6. Confirm the Wormhole VAA payload contains Arbitrum's chain ID and the attacker-triggered proxy address, demonstrating NEAR would register this unauthorized deployment.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L155-158)
```text
        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
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

**File:** near/omni-bridge/src/lib.rs (L84-84)
```rust
const SIGN_PATH: &str = "bridge-1";
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

**File:** starknet/src/omni_bridge.cairo (L205-205)
```text
            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
```

**File:** starknet/src/omni_bridge.cairo (L252-254)
```text
            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );
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
