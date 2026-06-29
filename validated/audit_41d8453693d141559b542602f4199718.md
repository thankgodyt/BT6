Audit Report

## Title
Cross-Chain Replay of `deployToken` Signature Due to Missing Chain ID in Borsh-Encoded `MetadataPayload` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`OmniBridge.deployToken` constructs its Borsh-encoded payload from only `PayloadType.Metadata`, `token`, `name`, `symbol`, and `decimals` — no chain identifier is included. Because the resulting `keccak256` digest is identical across every EVM deployment for the same NEAR token, a valid NEAR-issued signature authorizing deployment on chain A is unconditionally replayable on chain B. Any unprivileged observer can extract the calldata from chain A and submit it to chain B, deploying an unauthorized `BridgeToken` proxy and permanently blocking legitimate future deployment on that chain.

## Finding Description

`MetadataPayload` carries no chain field: [1](#0-0) 

`deployToken` hashes exactly those four fields with no `omniBridgeChainId`: [2](#0-1) 

The ECDSA check therefore passes on any chain for the same `(token, name, symbol, decimals)` tuple: [3](#0-2) 

The only replay guard is the per-contract `isBridgeToken` / `nearToEthToken` mapping, which only prevents a *second* deployment on the *same* chain — it provides no cross-chain protection: [4](#0-3) 

By contrast, `finTransfer` embeds `omniBridgeChainId` twice in its hash, binding the signature to a specific destination chain: [5](#0-4) 

`omniBridgeChainId` is a `uint8` state variable set at initialization and never referenced in the `deployToken` path: [6](#0-5) [7](#0-6) 

**Exploit flow:**
1. Attacker observes a successful `deployToken(signatureData, metadata)` transaction on chain A.
2. Attacker submits the identical `signatureData` and `metadata` to `deployToken` on chain B.
3. The Borsh-encoded preimage is identical; `keccak256` produces the same digest; `ECDSA.recover` returns `nearBridgeDerivedAddress`; the signature check passes.
4. A `BridgeToken` proxy is deployed on chain B and permanently bound to the NEAR token ID via `nearToEthToken` / `ethToNearToken` / `isBridgeToken`.
5. All subsequent legitimate `deployToken` calls for that NEAR token on chain B revert with `ERR_TOKEN_EXIST`.

Additionally, if two OmniBridge deployments share the same `omniBridgeChainId` value (the code enforces no uniqueness across deployments), `finTransfer` signatures become equally chain-agnostic, enabling a single NEAR-side lock event to mint on both chains. The `completedTransfers` nonce map is per-contract, so the same `destinationNonce` is unused on chain B: [8](#0-7) 

## Impact Explanation

The primary impact is a **chain/domain-separation flaw and authorization bypass**: NEAR never authorized token deployment on chain B, yet the attacker can deploy a bridge token there using a signature intended for chain A. This permanently blocks legitimate deployment on chain B (`ERR_TOKEN_EXIST` fires for all future calls), constituting irreversible disruption of the bridge's token registry on that chain. The secondary impact — when `omniBridgeChainId` collides across deployments — enables **unauthorized minting / double-spending** of bridged tokens without additional NEAR-side locking. Both impacts fall within the Critical allowed scope: cross-chain replay / chain/domain separation flaw enabling invalid finalization, and authorization bypass letting an attacker execute token-deployer-equivalent actions.

## Likelihood Explanation

The `deployToken` replay requires zero privileges and zero preconditions beyond chain A having processed at least one `deployToken` transaction. Any on-chain observer can extract the calldata and resubmit it. The attack is repeatable for every NEAR token ever deployed on any chain. The same-`omniBridgeChainId` precondition for double-minting is a misconfiguration, but the `uint8` space (256 values) is small and the code provides no uniqueness enforcement, making collisions plausible across many deployments.

## Recommendation

Include `omniBridgeChainId` in the Borsh-encoded `MetadataPayload` hash inside `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
+   bytes1(omniBridgeChainId),          // bind to destination chain
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

This requires NEAR to produce a separate signature per destination chain, matching the existing `finTransfer` design. Additionally, consider enforcing uniqueness of `omniBridgeChainId` values across deployments at the protocol level.

## Proof of Concept

```solidity
// Foundry test — two OmniBridge instances, different omniBridgeChainId
OmniBridge bridgeA = new OmniBridge(); bridgeA.initialize(impl, nearAddr, 1);
OmniBridge bridgeB = new OmniBridge(); bridgeB.initialize(impl, nearAddr, 2);

// NEAR signs MetadataPayload hash — no chain ID in preimage
bytes32 hash = keccak256(abi.encodePacked(
    bytes1(uint8(1)),          // PayloadType.Metadata
    borshString("token.near"),
    borshString("Token"),
    borshString("TKN"),
    bytes1(uint8(18))
));
(uint8 v, bytes32 r, bytes32 s) = vm.sign(nearPrivKey, hash);
bytes memory sig = abi.encodePacked(r, s, v);

BridgeTypes.MetadataPayload memory meta =
    BridgeTypes.MetadataPayload("token.near", "Token", "TKN", 18);

address addrA = bridgeA.deployToken(sig, meta); // succeeds on chain A
address addrB = bridgeB.deployToken(sig, meta); // succeeds on chain B — same sig, no chain binding

assert(addrA != addrB);
// Both chains now have an unauthorized BridgeToken bound to "token.near"
// All future legitimate deployToken calls on chain B revert with ERR_TOKEN_EXIST
```

### Citations

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L16-21)
```text
    struct MetadataPayload {
        string token;
        string name;
        string symbol;
        uint8 decimals;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L42-42)
```text
    uint8 public omniBridgeChainId;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L76-79)
```text
    ) public initializer {
        tokenImplementationAddress = tokenImplementationAddress_;
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
        omniBridgeChainId = omniBridgeChainId_;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L142-149)
```text
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(metadata.token),
            Borsh.encodeString(metadata.name),
            Borsh.encodeString(metadata.symbol),
            bytes1(metadata.decimals)
        );
        bytes32 hashed = keccak256(borshEncoded);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L151-153)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
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
