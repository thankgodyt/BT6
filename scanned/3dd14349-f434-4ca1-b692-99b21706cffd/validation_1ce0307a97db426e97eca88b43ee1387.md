### Title
MPC Signature Replay in `deployToken` After `removeCustomToken` Clears the Only Replay Guard — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`deployToken` has no per-signature nonce or "used" tracking. Its sole replay guard is `!isBridgeToken[nearToEthToken[metadata.token]]`. `removeCustomToken` deletes exactly the state that guard reads. An attacker who retains any previously broadcast `deployToken` calldata can replay it after an admin calls `removeCustomToken`, deploying a fresh `BridgeToken` proxy bound to the same NEAR token ID without any new MPC authorization.

---

### Finding Description

`deployToken` verifies the MPC signature and then checks:

```solidity
require(
    !isBridgeToken[nearToEthToken[metadata.token]],
    "ERR_TOKEN_EXIST"
);
``` [1](#0-0) 

There is no mapping of consumed signature hashes, no nonce in the `MetadataPayload`, and no entry in `completedTransfers` (which is only used by `finTransfer`). The signature covers only `(PayloadType.Metadata, token, name, symbol, decimals)` — a static payload that never changes for a given token. [2](#0-1) 

`removeCustomToken` deletes all three mappings the guard depends on:

```solidity
delete isBridgeToken[tokenAddress];
delete nearToEthToken[ethToNearToken[tokenAddress]];
delete ethToNearToken[tokenAddress];
``` [3](#0-2) 

After this deletion, `nearToEthToken[metadata.token]` returns `address(0)`, so `isBridgeToken[address(0)]` is `false`, and the guard passes for the replayed call.

**Attack sequence (all calldata is public on-chain):**

1. Attacker records `signatureData` and `metadata` from the original `deployToken` transaction.
2. Admin legitimately calls `removeCustomToken(A)` — clearing `isBridgeToken[A]`, `nearToEthToken["near.token"]`, and `ethToNearToken[A]`.
3. Attacker calls `deployToken(savedSignatureData, savedMetadata)`:
   - `ECDSA.recover(hashed, signatureData) == nearBridgeDerivedAddress` → **passes** (same payload, same signature, no nonce).
   - `!isBridgeToken[nearToEthToken["near.token"]]` → `!isBridgeToken[address(0)]` → `true` → **passes**.
   - A new `ERC1967Proxy` B is deployed and bound: `nearToEthToken["near.token"] = B`. [4](#0-3) 

The SECURITY.md note that "metadata signatures are intentionally chain-agnostic" addresses cross-chain replay (same signature on multiple EVM chains). It does not address same-chain replay after state is cleared. [5](#0-4) 

---

### Impact Explanation

- A new `BridgeToken` proxy is bound to the NEAR token ID without any new MPC threshold signature — one MPC signature authorizes an unbounded number of deployments as long as the admin keeps calling `removeCustomToken`.
- If the admin removed a custom-minter token (e.g., eNEAR registered via `addCustomToken`) and the attacker replays a `deployToken` signature for the same NEAR token ID, the canonical binding becomes a standard `BridgeToken` (no custom minter). Subsequent `finTransfer` calls for that token ID will mint standard `BridgeToken` supply instead of routing through the intended `ICustomMinter`, causing token accounting divergence and potential unauthorized minting.
- The attacker can permanently block the admin from re-registering the token: every time the admin calls `removeCustomToken` to clear the attacker's proxy, the attacker immediately replays the old signature again.

---

### Likelihood Explanation

- All `deployToken` calldata (including `signatureData`) is permanently visible on-chain. Any observer can save it at zero cost.
- `removeCustomToken` is a documented admin function with legitimate use cases (replacing a buggy token, upgrading implementation, fixing misconfiguration).
- No special privileges, leaked keys, or MPC collusion are required — only patience to watch for the admin's `removeCustomToken` transaction and replay before the admin's next action.

---

### Recommendation

Track consumed `deployToken` signature hashes in a `mapping(bytes32 => bool) public usedMetadataSignatures` and revert if the hash was already used:

```solidity
mapping(bytes32 => bool) public usedMetadataSignatures;

// inside deployToken, after computing `hashed`:
if (usedMetadataSignatures[hashed]) revert SignatureAlreadyUsed();
usedMetadataSignatures[hashed] = true;
```

This is consistent with the existing `completedTransfers` pattern used in `finTransfer` and matches the documented invariant: "a consumed MPC signature must never authorize a second state-changing action." [6](#0-5) 

---

### Proof of Concept

```typescript
it("replay deployToken after removeCustomToken succeeds without new MPC sig", async () => {
  // Step 1: deploy token T normally
  const { signature, payload } = await metadataSignature("wrap.testnet");
  const tx = await OmniBridge.deployToken(signature, payload);
  const receipt = await tx.wait();
  const proxyA = await OmniBridge.nearToEthToken("wrap.testnet");

  // Step 2: admin removes the token
  await OmniBridge.removeCustomToken(proxyA);
  expect(await OmniBridge.nearToEthToken("wrap.testnet")).to.equal(ethers.ZeroAddress);

  // Step 3: attacker replays the SAME signature and metadata — no new MPC sig
  const tx2 = await OmniBridge.connect(attacker).deployToken(signature, payload);
  const receipt2 = await tx2.wait();
  const proxyB = await OmniBridge.nearToEthToken("wrap.testnet");

  // A new proxy is bound without MPC re-authorization
  expect(proxyB).to.not.equal(ethers.ZeroAddress);
  expect(proxyB).to.not.equal(proxyA);
});
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L44-44)
```text
    mapping(uint64 => bool) public completedTransfers;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L123-126)
```text
        delete isBridgeToken[tokenAddress];
        delete nearToEthToken[ethToNearToken[tokenAddress]];
        delete ethToNearToken[tokenAddress];
        delete customMinters[tokenAddress];
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

**File:** evm/SECURITY.md (L10-10)
```markdown
- **`deployToken` signature has no chain ID**: Metadata signatures are intentionally chain-agnostic — one NEAR-side signature deploys the same token on all EVM chains
```
