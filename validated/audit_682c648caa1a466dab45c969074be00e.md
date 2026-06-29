Audit Report

## Title
Missing Chain Discriminator in `deployToken` Borsh Encoding Enables Cross-Chain Replay of NEAR MPC Signatures — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
The `deployToken` function constructs a Borsh-encoded payload for NEAR MPC signature verification that omits `omniBridgeChainId`. Because the same `nearBridgeDerivedAddress` is shared across all EVM deployments, a valid signature obtained from a `deployToken` call on chain A is cryptographically valid on chain B. An unprivileged attacker can replay the signature to deploy any bridged token on any chain without NEAR MPC authorization for that chain, permanently blocking the legitimate deployment and causing the NEAR bridge to record the token as authorized on chain B.

## Finding Description
In `OmniBridge.deployToken` (lines 142–148), the signed payload is:

```
PayloadType.Metadata | token | name | symbol | decimals
```

No `omniBridgeChainId` is included. The signature check at line 151 recovers against `nearBridgeDerivedAddress`, which is the same address across all EVM chain deployments. The only replay guard is the same-chain idempotency check at lines 155–158:

```solidity
require(
    !isBridgeToken[nearToEthToken[metadata.token]],
    "ERR_TOKEN_EXIST"
);
```

This check only prevents re-deployment on the *same* chain. It does not prevent replaying the signature on a *different* chain where the token has not yet been deployed.

By contrast, `finTransfer` (lines 289–308) encodes `omniBridgeChainId` **twice** in its signed payload, providing proper chain binding. The same structural omission exists in the Starknet implementation's `MetadataPayload.to_borsh()` (lines 36–44 of `starknet/src/bridge_types.cairo`), while `TransferMessagePayload.to_borsh()` (lines 61–71) correctly includes `chain_id`.

**Exploit path:**
1. Attacker observes a valid `deployToken` transaction on chain A (signature is public on-chain).
2. Attacker calls `deployToken` on chain B with the identical `signatureData` and `MetadataPayload`.
3. Signature verification passes: the Borsh payload is chain-agnostic, so `ECDSA.recover` returns `nearBridgeDerivedAddress`.
4. The `ERR_TOKEN_EXIST` check passes because the token has not been deployed on chain B yet.
5. A `BridgeToken` proxy is deployed on chain B and mappings are populated (`isBridgeToken`, `nearToEthToken`, `ethToNearToken`).
6. `OmniBridgeWormhole.deployTokenExtension` publishes a Wormhole message containing `omniBridgeChainId` for chain B, causing the NEAR bridge to record the token as legitimately deployed on chain B.
7. Any future authorized `deployToken` call for that token on chain B will revert with `ERR_TOKEN_EXIST`.

## Impact Explanation
This is a **chain/domain separation flaw** enabling unauthorized token deployment and authorization bypass. After a successful replay: the NEAR bridge records the token as deployed on chain B; subsequent `finTransfer` calls to chain B for that token will mint tokens against the replayed (unauthorized) contract; and the legitimate deployment of that token on chain B is permanently blocked. This matches the allowed critical impact class: *"Cross-chain replay … or chain/domain separation flaw enabling invalid finalization"* and *"Unauthorized transaction, authorization bypass … that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."*

## Likelihood Explanation
- The precondition (shared `nearBridgeDerivedAddress` across all EVM deployments) is the intended production model.
- `deployToken` is a permissionless `external` function with no role check or allowlist.
- The required `signatureData` is observable on-chain from any prior `deployToken` call on any chain.
- The attack is a single transaction on the target chain, requiring no special privileges or victim interaction.
- The attack is repeatable for every token not yet deployed on the target chain.

## Recommendation
Include `omniBridgeChainId` in the Borsh-encoded bytes signed for `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals),
    bytes1(omniBridgeChainId)   // add chain binding
);
```

Apply the same fix to `MetadataPayload.to_borsh()` in `starknet/src/bridge_types.cairo` and ensure the NEAR MPC signing logic includes the destination chain ID when producing `MetadataPayload` signatures.

## Proof of Concept
```solidity
// Local Hardhat test — no mainnet interaction required
// 1. Deploy two OmniBridgeWormhole instances sharing the same
//    nearBridgeDerivedAddress but with different omniBridgeChainId
//    values (e.g., 0 for Ethereum, 1 for Arbitrum).
// 2. Call deployToken on chain A (omniBridgeChainId=0) with a valid
//    NEAR MPC signature; record the emitted signatureData.
// 3. Call deployToken on chain B (omniBridgeChainId=1) with the
//    identical signatureData and MetadataPayload.
// 4. Assert the call succeeds: nearToEthToken[token] != address(0)
//    on chain B, isBridgeToken[...] == true, DeployToken event emitted.
// 5. Attempt a legitimate deployToken call for the same token on
//    chain B; assert it reverts with ERR_TOKEN_EXIST.
// 6. Confirm chain A's signature was accepted on chain B without any
//    chain-B-specific authorization from NEAR MPC.
```