### Title
Cross-Chain Replay of `deployToken` Signature Enables Unauthorized Token Deployment on Unintended EVM Chains — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` verifies a NEAR-MPC-generated signature over a Borsh-encoded payload that contains only token metadata (type byte, token ID, name, symbol, decimals). No chain identifier — neither `block.chainid` nor the contract's own `omniBridgeChainId` — is included in the signed hash. Because the same `OmniBridge` contract is deployed on multiple EVM chains (Ethereum, Arbitrum, Base, Polygon, BNB), a valid `deployToken` signature observed on one chain can be replayed verbatim on every other chain, deploying bridge tokens on chains the NEAR bridge never authorized.

---

### Finding Description

In `OmniBridge.sol`, `deployToken` constructs the signed message as:

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

The hash is purely a function of the token metadata. There is no `block.chainid`, no `address(this)`, and no `omniBridgeChainId` field. Compare this with `finTransfer`, which does embed `omniBridgeChainId` in its Borsh payload:

```solidity
bytes1(omniBridgeChainId),
Borsh.encodeAddress(payload.tokenAddress),
``` [2](#0-1) 

`deployToken` has no equivalent binding. The `MetadataPayload` struct contains only `token`, `name`, `symbol`, and `decimals`: [3](#0-2) 

The same structural omission exists in the Starknet bridge. `MetadataPayload::to_borsh()` serializes only the type byte, token, name, symbol, and decimals — no chain ID: [4](#0-3) 

And in the Solana bridge, `DeployTokenPayload::serialize_for_near` similarly omits any chain identifier: [5](#0-4) 

The only replay guard in `deployToken` is the idempotency check `require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST")`, which only prevents re-use on the **same** chain after the token is already deployed there. [6](#0-5) 

---

### Impact Explanation

An attacker who observes a legitimate `deployToken` transaction on chain A (e.g., Ethereum) can submit the identical `(signatureData, metadata)` calldata to `OmniBridge` on chains B, C, D, … (Arbitrum, Base, Polygon, BNB). Each call passes signature verification because the hash is chain-agnostic.

Consequences:

1. **Unauthorized token deployment**: Bridge tokens are deployed on chains the NEAR bridge never authorized, and are immediately registered in `nearToEthToken` / `ethToNearToken` mappings.
2. **Permanent blocking of legitimate deployment**: Once the token exists on a chain (`isBridgeToken[addr] == true`), the NEAR bridge can never call `deployToken` for that token on that chain again. The only recovery path is an admin `addCustomToken` call, which requires recognizing the attacker-triggered contract as the canonical token.
3. **Minting risk on attacker-triggered chains**: If the NEAR bridge later legitimately supports the chain, `finTransfer` will mint into the attacker-deployed token contract (which is owned by the bridge, so minting itself is correct), but the deployment event was unauthorized and the chain was not yet configured — creating a window where the token exists but the NEAR bridge has no corresponding state for it.

The impact class is **unauthorized bridge action / cross-chain replay enabling unauthorized token deployment and permanent state manipulation of the bridge's token registry**.

---

### Likelihood Explanation

- The `OmniBridge` contract is publicly deployed on at least five EVM chains simultaneously (Ethereum, Arbitrum, Base, Polygon, BNB).
- `deployToken` is a permissionless external function callable by any address.
- Any `deployToken` transaction on any chain is publicly visible on-chain.
- No special knowledge, privilege, or front-running is required — the attacker simply copies the calldata and submits it to another chain's `OmniBridge`.
- The NEAR bridge regularly deploys new tokens as the ecosystem grows, providing a continuous stream of replayable signatures.

Likelihood is **high**.

---

### Recommendation

Include a chain-binding field in the signed Borsh payload for `deployToken`. The most straightforward fix mirrors what `finTransfer` already does: prepend `omniBridgeChainId` (or `block.chainid`) into the encoded bytes before hashing.

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // <-- add chain binding
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

The NEAR bridge's signature-generation logic must be updated in lockstep to include the target chain ID when producing `deployToken` signatures. Apply the equivalent fix to the Starknet `MetadataPayload::to_borsh()` and Solana `DeployTokenPayload::serialize_for_near`.

---

### Proof of Concept

1. The NEAR bridge calls `deployToken(sig, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` on Ethereum (`OmniBridge` at `0xAAA…`). Transaction is mined and visible on-chain.

2. Attacker copies the exact calldata (same `sig`, same `metadata`) and submits it to `OmniBridge` on Arbitrum (`0xBBB…`), Base (`0xCCC…`), Polygon, and BNB.

3. On each chain, `ECDSA.recover(keccak256(borshEncoded), sig)` returns `nearBridgeDerivedAddress` (identical hash, identical signature, identical signer check) — all calls succeed.

4. `usdc.near` bridge tokens are now deployed on all five chains. The NEAR bridge only authorized Ethereum.

5. When the NEAR bridge later tries to legitimately deploy `usdc.near` on Arbitrum, the call reverts with `"ERR_TOKEN_EXIST"`. The bridge's token registry is permanently corrupted for that chain unless an admin intervenes.

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
