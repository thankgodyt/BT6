Audit Report

## Title
Missing Contract Address Binding in `finTransfer` Message Hash Enables Cross-Deployment Signature Replay — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
The `finTransfer` function in `OmniBridge.sol` constructs its Borsh-encoded message hash without including `address(this)`. The only chain-binding field is `omniBridgeChainId`, a 1-byte `ChainKind` enum value that identifies the chain type (e.g., `0` for all Ethereum-family deployments), not the specific contract instance. Because `nearBridgeDerivedAddress` is the same NEAR MPC-derived key across all deployments sharing the same NEAR bridge contract, any valid `finTransfer` signature can be replayed verbatim on any other `OmniBridge` deployment on the same chain that shares the same `omniBridgeChainId`, enabling double-spending of bridged funds.

## Finding Description

In `OmniBridge.sol::finTransfer()` (L289–313), the hash is assembled as:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
    Borsh.encodeUint64(payload.destinationNonce),
    bytes1(payload.originChain),
    Borsh.encodeUint64(payload.originNonce),
    bytes1(omniBridgeChainId),          // ChainKind enum, e.g. 0 = Eth
    Borsh.encodeAddress(payload.tokenAddress),
    Borsh.encodeUint128(payload.amount),
    bytes1(omniBridgeChainId),          // repeated for recipient chain
    Borsh.encodeAddress(payload.recipient),
    ...
);
bytes32 hashed = keccak256(borshEncoded);
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

`omniBridgeChainId` is a storage variable set at initialization to a `ChainKind` enum byte — `0` for Ethereum, `3` for Arbitrum, etc. — not the EVM `block.chainid`. Two different `OmniBridge` contracts deployed on Ethereum both store `omniBridgeChainId = 0`. The `nearBridgeDerivedAddress` is also set at initialization and is the same NEAR MPC-derived key for all deployments backed by the same NEAR bridge contract.

The `completedTransfers` mapping is per-contract storage (`mapping(uint64 => bool)`). A freshly deployed contract has an empty bitmap. The `destination_nonce` is assigned by the NEAR bridge per destination chain kind (not per EVM contract address), so nonce `N` for `ChainKind::Eth` is globally unique on NEAR but is not bound to any specific EVM contract address in the signed payload.

The NEAR signing path (`near/omni-bridge/src/lib.rs` L491–506) calls `transfer_payload.encode_hashable()` which serializes `TransferMessagePayload` via Borsh — this struct contains no EVM contract address field. The EVM-side hash is therefore structurally identical for any two Ethereum-deployed `OmniBridge` contracts receiving the same transfer payload.

The `SECURITY.md` explicitly acknowledges that `deployToken` signatures are intentionally chain-agnostic, but makes no such acknowledgment for `finTransfer`, confirming this is not an intended design decision.

## Impact Explanation

This is a **Critical** cross-chain domain separation flaw enabling double-spending of bridged funds. An attacker who observes any legitimate `finTransfer` transaction (all calldata is public on-chain) can replay the identical signature and payload on any newly deployed `OmniBridge` contract on the same chain sharing the same `omniBridgeChainId` and `nearBridgeDerivedAddress`. The new contract's `completedTransfers` mapping starts empty, the hash is identical (no `address(this)`), `ECDSA.recover` returns `nearBridgeDerivedAddress`, and the attacker receives a second disbursement of the same tokens. This matches the allowed Critical impact: "Cross-chain replay, chain/domain separation flaw enabling invalid finalization or double-spending."

## Likelihood Explanation

Moderate. The attack requires a second `OmniBridge` deployment on the same chain with the same `omniBridgeChainId` and `nearBridgeDerivedAddress`. This is a realistic operational scenario: bridge migrations, security-incident redeployments, or parallel bridge instances. The attacker requires no special privileges — only access to historical on-chain calldata, which is fully public. Once a second deployment exists, every historical `finTransfer` signature becomes replayable, and the attacker can drain the new contract's token holdings by replaying all historical nonces.

## Recommendation

Include `address(this)` in the `borshEncoded` message hash inside `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
    Borsh.encodeUint64(payload.destinationNonce),
    bytes1(payload.originChain),
    Borsh.encodeUint64(payload.originNonce),
    bytes1(omniBridgeChainId),
+   Borsh.encodeAddress(address(this)),   // bind to this specific contract
    Borsh.encodeAddress(payload.tokenAddress),
    Borsh.encodeUint128(payload.amount),
    bytes1(omniBridgeChainId),
    Borsh.encodeAddress(payload.recipient),
    ...
);
```

The NEAR signing path in `TransferMessagePayload::encode_hashable()` must be updated in parallel to include the destination EVM contract address in the serialized payload. Apply the same fix to the Starknet `fin_transfer` by including `get_contract_address()` in `to_borsh`. Optionally also include `block.chainid` for fork protection.

## Proof of Concept

1. User initiates a NEAR→Ethereum transfer. NEAR MPC signs a `TransferMessagePayload` with `destinationNonce = 42`, `amount = 10,000 USDC`, `recipient = attacker`, `omniBridgeChainId = 0`.
2. Relayer calls `finTransfer` on `OmniBridge` at `0xOLD`. `completedTransfers[42]` is `false` → set to `true`. Signature verifies. 10,000 USDC minted to attacker.
3. Bridge team deploys a new `OmniBridge` at `0xNEW` on Ethereum with the same `omniBridgeChainId = 0` and same `nearBridgeDerivedAddress`. `completedTransfers` is empty.
4. Attacker calls `finTransfer` on `0xNEW` with the identical `signatureData` and `payload` from step 2.
   - `completedTransfers[42]` on `0xNEW` is `false` → nonce check passes.
   - `borshEncoded` is byte-for-byte identical (no `address(this)`) → `keccak256` produces the same hash → `ECDSA.recover` returns `nearBridgeDerivedAddress` → signature check passes.
   - Another 10,000 USDC is minted to attacker.
5. Attacker repeats for every historical `finTransfer` nonce (all public on-chain), draining `0xNEW`.

A local integration test can demonstrate this by deploying two `OmniBridge` instances with the same constructor parameters, executing `finTransfer` on the first with a test MPC signature, then replaying the identical calldata on the second and asserting the token balance increases on both.