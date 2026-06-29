Now I have all the information needed. Let me analyze the exact code paths.

**Key finding:** The `deployToken` Borsh-encoded payload in `OmniBridge.sol` (lines 142–148) is:

```
PayloadType.Metadata | token | name | symbol | decimals
```

No `omniBridgeChainId` is included. Compare this to `finTransfer` (lines 289–308), which explicitly embeds `omniBridgeChainId` twice. The `omniBridgeChainId` is only added to the *Wormhole outbound message* in `deployTokenExtension` (line 57 of `OmniBridgeWormhole.sol`), not to the *signature verification input*.

Since the NEAR MPC key (`nearBridgeDerivedAddress`) is the same across all EVM deployments by design, a valid `deployToken` signature for chain A is cryptographically identical to a valid signature for chain B.

---

### Title
Cross-Chain Replay of `deployToken` ECDSA Signature Enables Unauthorized Token Binding on Unintended EVM Chains — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.deployToken` verifies a NEAR MPC ECDSA signature over a Borsh-encoded `MetadataPayload` that contains no destination chain identifier. Because all `OmniBridgeWormhole` deployments share the same `nearBridgeDerivedAddress`, a signature obtained for chain A is valid on chain B, allowing an attacker to replay it and create an unauthorized bridge-token binding on chain B.

### Finding Description
In `OmniBridge.deployToken`, the signed message is constructed as:

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

`omniBridgeChainId` is a stored field on the contract: [2](#0-1) 

but it is **never included** in the `deployToken` signature payload. By contrast, `finTransfer` correctly embeds `omniBridgeChainId` twice: [3](#0-2) 

`omniBridgeChainId` only appears in the *outbound Wormhole message* emitted after deployment: [4](#0-3) 

The `BridgeTypes.MetadataPayload` struct itself has no chain field: [5](#0-4) 

The same is true on Starknet — `MetadataPayload.to_borsh()` also omits any chain ID: [6](#0-5) 

### Impact Explanation
1. Attacker captures a valid `deployToken(sig, metadata)` call on chain A (e.g., Ethereum).
2. Attacker calls `deployToken(sig, metadata)` on chain B (e.g., Polygon) with the identical arguments.
3. Signature verification passes because the hash is chain-agnostic and `nearBridgeDerivedAddress` is identical on both deployments.
4. `nearToEthToken[metadata.token]` is populated on chain B and `isBridgeToken[newProxy]` is set to `true`. [7](#0-6) 
5. `deployTokenExtension` emits a Wormhole `DeployToken` message from chain B to NEAR, registering the token binding on NEAR for chain B. [8](#0-7) 
6. Once NEAR registers the binding, legitimate `finTransfer` calls on chain B (with valid chain-B-scoped signatures) can mint tokens against the unauthorized proxy, because `isBridgeToken[proxy]` is `true` and the `finTransfer` path mints to any address marked as a bridge token. [9](#0-8) 

The invariant broken is: *a NEAR-signed token-deployment authorization must be scoped to exactly one destination chain*. The missing chain binding in the signed payload violates this invariant across every EVM (and Starknet) deployment that shares the same MPC key.

### Likelihood Explanation
- **Precondition is always met in production**: `nearBridgeDerivedAddress` is the NEAR MPC-derived address, which is a single key used across all chain deployments by design.
- **No privileged access required**: `deployToken` is a public, permissionless function gated only by the signature check and the `ERR_TOKEN_EXIST` guard (which passes on any chain where the token hasn't been deployed yet).
- **Replay material is public**: `deployToken` transactions are on-chain and the calldata is fully visible.
- **One-time per token per chain**: The `ERR_TOKEN_EXIST` guard prevents double-deployment on the same chain, but does not prevent cross-chain replay.

### Recommendation
Include `omniBridgeChainId` in the Borsh-encoded payload that is signed and verified in `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals),
    bytes1(omniBridgeChainId)   // <-- add this
);
```

Apply the equivalent fix to the Starknet `MetadataPayload.to_borsh()` and the Solana `DeployTokenPayload::serialize_for_near()` implementations, and update the NEAR MPC signing logic to include the destination chain ID when producing metadata signatures.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Pseudocode — run against two local OmniBridgeWormhole instances
// with the same nearBridgeDerivedAddress (= testWallet.address)

// 1. Deploy bridgeA (chainId=1) and bridgeB (chainId=2),
//    both initialized with nearBridgeDerivedAddress = testWallet.address

// 2. Obtain a valid deployToken call on bridgeA:
//    (sig, metadata) = metadataSignature("token.near")  // no chain ID in payload
//    bridgeA.deployToken{value: fee}(sig, metadata)     // succeeds on chain A

// 3. Replay the identical (sig, metadata) on bridgeB:
//    bridgeB.deployToken{value: fee}(sig, metadata)     // also succeeds — no revert

// 4. Assert unauthorized binding on chain B:
//    address proxyB = bridgeB.nearToEthToken("token.near");
//    assert(proxyB != address(0));
//    assert(bridgeB.isBridgeToken(proxyB) == true);

// 5. The Wormhole DeployToken message emitted from bridgeB notifies NEAR,
//    which registers the token for chain B.
//    Subsequent finTransfer calls on bridgeB with valid chain-B signatures
//    will mint against proxyB — an unintended token contract.
```

The test helper in `evm/tests/helpers/signatures.ts` confirms the signed `MetadataMessage` schema contains no chain ID field: [10](#0-9)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L42-42)
```text
    uint8 public omniBridgeChainId;
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-308)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-349)
```text
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L48-69)
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

**File:** evm/tests/helpers/signatures.ts (L16-37)
```typescript
class MetadataMessage {
  static schema = {
    struct: {
      payloadType: "u8",
      token: "string",
      name: "string",
      symbol: "string",
      decimals: "u8",
    },
  }

  constructor(
    public payloadType: number,
    public token: string,
    public name: string,
    public symbol: string,
    public decimals: BigNumberish,
  ) {}

  static serialize(msg: MetadataMessage): Uint8Array {
    return borsh.serialize(MetadataMessage.schema, msg)
  }
```
