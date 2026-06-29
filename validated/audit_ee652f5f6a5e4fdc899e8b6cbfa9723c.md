The code confirms this is a real vulnerability. Let me walk through the exact evidence.

**The `deployToken` hash construction** in `OmniBridge.sol`: [1](#0-0) 

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
bytes32 hashed = keccak256(borshEncoded);
```

No chain ID of any kind is included — not `omniBridgeChainId`, not the EVM `block.chainid`, not the contract address.

**Contrast with `finTransfer`**, which correctly includes `omniBridgeChainId` twice: [2](#0-1) 

The `deployToken` hash is purely a function of `(PayloadType, token, name, symbol, decimals)`. A signature over this hash is valid on every EVM chain where the same NEAR bridge is deployed, regardless of `omniBridgeChainId` values.

**The only replay guard** in `deployToken` is: [3](#0-2) 

This only prevents deploying the same token twice on the **same** chain instance. It provides zero protection against cross-chain replay.

---

### Title
Cross-Chain Signature Replay in `deployToken` Due to Missing Chain ID in Borsh-Encoded Hash — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`deployToken` verifies a NEAR-signed ECDSA signature over a Borsh-encoded `MetadataPayload` that contains no chain identifier. A signature authorizing token deployment on one EVM chain is cryptographically valid on every other EVM chain where the OmniBridge is deployed.

### Finding Description
The signed preimage for `deployToken` is:

```
keccak256( PayloadType::Metadata || encodeString(token) || encodeString(name) || encodeString(symbol) || bytes1(decimals) )
```

None of `omniBridgeChainId`, `block.chainid`, or the contract address appear in this preimage. Because `finTransfer` does embed `omniBridgeChainId` in its hash, the omission in `deployToken` is inconsistent and unintentional.

An attacker who observes a successful `deployToken(sig, metadata)` call on chain A can submit the identical calldata on chain B. `ECDSA.recover` will return `nearBridgeDerivedAddress` on chain B, the `isBridgeToken` guard passes (the token has not been deployed on chain B yet), and a new `BridgeToken` proxy is deployed and registered in `nearToEthToken[metadata.token]` on chain B.

The precondition stated in the question (same `omniBridgeChainId` on both chains) is actually **not required** — the attack succeeds even when the two chains have different `omniBridgeChainId` values, because that field is absent from the hash entirely.

### Impact Explanation
- **Unauthorized token deployment**: An attacker can deploy any NEAR-bridged token on any supported EVM chain using a signature NEAR issued for a different chain, without NEAR explicitly authorizing that chain.
- **`nearToEthToken` binding pollution**: Once the attacker-triggered deployment registers `nearToEthToken[token] = attackerDeployedProxy`, a legitimate NEAR-authorized deployment on that chain is permanently blocked (`ERR_TOKEN_EXIST`).
- **Potential double-minting path**: If NEAR's off-chain relayer observes the token as "deployed" on chain B and begins countersigning `finTransfer` messages for chain B (which do include `omniBridgeChainId` and are therefore chain-specific), users can receive minted tokens on chain B backed by the same NEAR-locked funds that were already used for chain A transfers.

### Likelihood Explanation
The attack requires only: (1) observing a valid `deployToken` transaction on any public EVM chain (trivially done via block explorer), and (2) submitting the same calldata on another chain. No privileged access, no key material, no admin compromise. Any permissionless actor can execute this.

### Recommendation
Include a chain-binding commitment in the signed preimage, consistent with how `finTransfer` already handles it:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // add this
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

NEAR's signing logic must be updated in lockstep to include the destination chain ID when producing `deployToken` signatures.

### Proof of Concept
```solidity
// Foundry test — two OmniBridge instances, different omniBridgeChainId values
OmniBridge bridgeA = new OmniBridge(); bridgeA.initialize(..., nearSigner, 1);
OmniBridge bridgeB = new OmniBridge(); bridgeB.initialize(..., nearSigner, 42);

BridgeTypes.MetadataPayload memory meta = BridgeTypes.MetadataPayload({
    token: "token.near", name: "Token", symbol: "TKN", decimals: 18
});

// NEAR signs hash with NO chain ID — identical on both chains
bytes32 hash = keccak256(abi.encodePacked(
    bytes1(uint8(PayloadType.Metadata)),
    Borsh.encodeString(meta.token),
    Borsh.encodeString(meta.name),
    Borsh.encodeString(meta.symbol),
    bytes1(meta.decimals)
));
bytes memory sig = sign(nearPrivKey, hash);

address addrA = bridgeA.deployToken(sig, meta); // succeeds — intended
address addrB = bridgeB.deployToken(sig, meta); // succeeds — replay, unintended

assert(addrA != address(0));
assert(addrB != address(0)); // both deployments succeed with the same signature
```

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L155-158)
```text
        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
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
