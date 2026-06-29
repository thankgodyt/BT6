The code confirms the claim. Let me verify the key facts:

1. `OmniBridge.sol::deployToken` (L142-153): no `omniBridgeChainId` in the hash — confirmed.
2. `OmniBridge.sol::finTransfer` (L294, L297): includes `omniBridgeChainId` twice — confirmed.
3. `MetadataPayload` in `near/omni-types/src/lib.rs` (L694-702): no chain field — confirmed.
4. Starknet `deploy_token` (L205): calls `payload.to_borsh()` with no chain_id — confirmed.
5. Starknet `fin_transfer` (L252-254): calls `payload.to_borsh(self.omni_bridge_chain_id.read())` — confirmed.
6. `SIGN_PATH = "bridge-1"` (L84): single MPC path, same derived address across all EVM chains — confirmed.

---

Audit Report

## Title
Missing Chain ID in `deployToken` Signature Enables Cross-Chain Replay Across EVM Deployments — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
The `deployToken` function in `OmniBridge.sol` verifies a NEAR MPC signature over a borsh-encoded payload that excludes `omniBridgeChainId`. Because the same MPC key path (`bridge-1`) produces the same `nearBridgeDerivedAddress` on every EVM deployment, a valid `deployToken` signature obtained for one EVM chain (e.g., Ethereum) can be replayed verbatim on any other EVM chain (Arbitrum, Base, BNB) to deploy a bridge token without chain-specific NEAR authorization. The Starknet `deploy_token` has the identical structural gap.

## Finding Description
In `OmniBridge.sol::deployToken`, the signed payload is constructed as:

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

No chain identifier is included. By contrast, `finTransfer` encodes `omniBridgeChainId` twice: [2](#0-1) 

The NEAR MPC signing key path is a single constant `"bridge-1"`: [3](#0-2) 

This means the derived Ethereum address (`nearBridgeDerivedAddress`) is identical across all EVM deployments. The `MetadataPayload` struct contains no chain field: [4](#0-3) 

On Starknet, `deploy_token` calls `payload.to_borsh()` with no chain_id argument: [5](#0-4) 

While `fin_transfer` correctly passes `self.omni_bridge_chain_id.read()`: [6](#0-5) 

And `MetadataPayloadImpl::to_borsh` accepts no chain_id parameter: [7](#0-6) 

**Exploit flow:**
1. Attacker observes a confirmed `deployToken(signatureData, metadata)` call on Ethereum (fully public).
2. Attacker submits the identical calldata to the Arbitrum `OmniBridgeWormhole` contract.
3. Arbitrum computes the same `keccak256(borshEncoded)` (no chain ID), recovers the same `nearBridgeDerivedAddress`, and accepts the signature.
4. A `BridgeToken` proxy for `metadata.token` is deployed; `isBridgeToken[proxy] = true`, `nearToEthToken[metadata.token] = proxy` are set.
5. `OmniBridgeWormhole::deployTokenExtension` publishes a Wormhole VAA back to NEAR with `omniBridgeChainId` (Arbitrum's ID) and the new proxy address. [8](#0-7) 
6. NEAR processes the VAA and registers the token as deployed on Arbitrum.
7. Any subsequent legitimate `deployToken` for the same token on Arbitrum reverts with `ERR_TOKEN_EXIST`: [9](#0-8) 

The existing `ERR_TOKEN_EXIST` guard is insufficient — it only prevents double-deployment, not replay from another chain. There is no nonce, no chain binding, and no other guard in `deployToken` that would reject a cross-chain replay.

## Impact Explanation
This is a **signer/prover verification bypass** that lets an unprivileged external attacker execute a **deployer-equivalent action** — deploying bridge tokens on EVM chains without chain-specific NEAR authorization. This matches the Critical allowed impact: *"Unauthorized transaction, authorization bypass, role bypass, pause bypass, or signer/prover verification bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."* It also matches: *"Cross-chain replay … or chain/domain separation flaw enabling invalid finalization."* The attacker forces token registration on chains NEAR never authorized, and permanently blocks the legitimate authorized deployment for that token on the target chain by setting `nearToEthToken[metadata.token]` to an attacker-triggered proxy address.

## Likelihood Explanation
Exploitation requires zero privileged access. The attacker only needs to read a confirmed `deployToken` transaction from any public block explorer and submit the same calldata to a different EVM chain's bridge contract. No private keys, no MEV infrastructure, no victim interaction. The only precondition is that the target chain's bridge contract is live and unpaused. The attack is repeatable across every EVM chain deployment (Arbitrum, Base, BNB, Polygon, HyperEVM, Abstract) for every token that has ever been deployed on any one of them.

## Recommendation
Include `omniBridgeChainId` in the borsh-encoded payload for `deployToken`, mirroring the pattern already used in `finTransfer`:

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

Apply the same fix to `MetadataPayloadImpl::to_borsh` in `starknet/src/bridge_types.cairo` — add a `chain_id: u8` parameter and embed it, matching `TransferMessagePayloadImpl::to_borsh`. Update the NEAR signing logic to include the destination chain in `MetadataPayload` before hashing, and update `MetadataPayload` in `near/omni-types/src/lib.rs` to carry a chain field.

## Proof of Concept
1. On Ethereum mainnet, locate any confirmed `deployToken(signatureData, metadata)` transaction (e.g., via Etherscan).
2. Submit the identical `(signatureData, metadata)` calldata to the Arbitrum `OmniBridgeWormhole` contract address.
3. Observe that the Arbitrum contract computes the same `keccak256(borshEncoded)`, recovers the same `nearBridgeDerivedAddress`, and does not revert on `InvalidSignature`.
4. Confirm that `nearToEthToken[metadata.token]` is now set on Arbitrum to a newly deployed `BridgeToken` proxy.
5. Confirm that `OmniBridgeWormhole::deployTokenExtension` emitted a Wormhole VAA with Arbitrum's `omniBridgeChainId`.
6. Attempt a legitimate `deployToken` for the same `metadata.token` on Arbitrum — observe it reverts with `ERR_TOKEN_EXIST`.

A local integration test can reproduce steps 2–6 by deploying two instances of `OmniBridgeWormhole` with different `omniBridgeChainId` values but the same `nearBridgeDerivedAddress`, calling `deployToken` on the first, capturing the calldata, and replaying it on the second.

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
