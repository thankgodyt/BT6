### Title
Re-org Attack on `deployToken` via CREATE-based Proxy Deployment Causes Token Metadata Binding Confusion — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.deployToken` deploys bridge token proxies using the `new ERC1967Proxy(...)` constructor, which uses the EVM `CREATE` opcode. The resulting address is derived solely from the `OmniBridge` contract's nonce. On EVM chains where re-orgs occur (particularly L2s such as Polygon, Arbitrum, Base, and BNB Chain — all supported deployment targets), a re-org can shift the nonce at the moment of deployment, causing a different token's proxy to land at the address that the NEAR side has already recorded for the original token. This produces a permanent token metadata binding confusion between two distinct bridge tokens, enabling fund theft.

### Finding Description

`deployToken` in `OmniBridge.sol` deploys a new `ERC1967Proxy` using the plain `new` keyword:

```solidity
address bridgeTokenProxy = address(
    new ERC1967Proxy(
        tokenImplementationAddress,
        abi.encodeWithSelector(
            BridgeToken.initialize.selector,
            metadata.name,
            metadata.symbol,
            decimals
        )
    )
);
``` [1](#0-0) 

The `CREATE` opcode derives the deployed address from `keccak256(rlp(deployer_address, nonce))`. If any other contract-creating transaction is inserted before this call during a re-org, the nonce increments and the proxy lands at a different address than the one already recorded by the NEAR bridge.

After deployment, `OmniBridgeWormhole.deployTokenExtension` immediately publishes a Wormhole VAA containing the deployed address:

```solidity
bytes memory payload = bytes.concat(
    bytes1(uint8(MessageType.DeployToken)),
    Borsh.encodeString(token),
    bytes1(omniBridgeChainId),
    Borsh.encodeAddress(tokenAddress),
    ...
);
_wormhole.publishMessage{value: msg.value}(wormholeNonce, payload, _consistencyLevel);
``` [2](#0-1) 

Once Wormhole guardians attest the VAA and the NEAR side processes it, the NEAR bridge permanently records `token_X → address_A`. If a re-org then causes a different token's proxy to occupy `address_A`, the NEAR-side mapping is permanently wrong.

The `deployToken` signature covers only `(token, name, symbol, decimals)` with no nonce, no caller binding, and no chain-specific salt:

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

This means any previously issued MPC signature for any token can be replayed by any caller at any time, making it straightforward for an attacker to insert a `deployToken` call for a different token during a re-org window.

### Impact Explanation

After a successful re-org:

- NEAR records `token_X → address_A`, but `address_A` is now the proxy for `token_Y`.
- NEAR records `token_Y → address_B`, but `address_B` is now the proxy for `token_X`.

Any user bridging `token_X` from NEAR to EVM will have `token_Y` minted to them (and vice versa). An attacker who controls `token_Y` (or who holds `token_Y` on EVM) can exploit the inverted mapping to extract value: bridge `token_Y` from EVM to NEAR (receiving `token_X` credit on NEAR), then bridge back, effectively double-spending or draining the escrow of the higher-value token. This is a direct token metadata binding confusion causing loss of bridged funds.

### Likelihood Explanation

The bridge is explicitly deployed on Polygon, Arbitrum, Base, and BNB Chain — all chains with documented re-org histories. Polygon suffered a 157-block re-org in 2023. The Wormhole consistency level for these chains is configurable and may be set low (fast finality), meaning guardians can attest a VAA before the underlying block is truly final. Two legitimate `deployToken` calls submitted in the same block (a normal operational scenario when multiple tokens are being onboarded) are sufficient; no attacker-controlled MPC key is needed. The attacker only needs to replay a previously issued, publicly visible MPC signature for a second token during the re-org window, which is trivially achievable since signatures are not caller-bound or nonce-protected.

### Recommendation

Replace `new ERC1967Proxy(...)` with a `CREATE2`-based deployment using a salt that commits to the token identity:

```solidity
bytes32 salt = keccak256(abi.encodePacked(metadata.token));
address bridgeTokenProxy = address(
    new ERC1967Proxy{salt: salt}(
        tokenImplementationAddress,
        abi.encodeWithSelector(
            BridgeToken.initialize.selector,
            metadata.name,
            metadata.symbol,
            decimals
        )
    )
);
```

This makes the deployed address a deterministic function of the NEAR token identifier, independent of the contract nonce, eliminating the re-org surface. Additionally, bind the MPC signature to a chain ID and a contract-level nonce to prevent replay of previously issued deployment signatures.

### Proof of Concept

1. The NEAR MPC network issues two valid `deployToken` signatures: `sig_X` for `token_X` and `sig_Y` for `token_Y`. Both are broadcast publicly (e.g., via a relayer).
2. A relayer submits `deployToken(sig_X, metadata_X)` in block N. `OmniBridge` nonce = 5 → proxy for `token_X` lands at `address_A`. Wormhole VAA is published and attested: `token_X → address_A`.
3. The NEAR bridge processes the VAA and records `token_X → address_A`.
4. A re-org drops block N. An attacker front-runs by submitting `deployToken(sig_Y, metadata_Y)` first in the replacement block N′. `OmniBridge` nonce = 5 → proxy for `token_Y` lands at `address_A`.
5. The original `deployToken(sig_X, metadata_X)` is re-included in block N′+1. `OmniBridge` nonce = 6 → proxy for `token_X` lands at `address_B`.
6. NEAR now has `token_X → address_A` (stale, from the pre-reorg VAA), but `address_A` is the `token_Y` proxy.
7. The attacker bridges `token_Y` from EVM (burning from `address_A`) and receives `token_X` credit on NEAR, then bridges `token_X` back to EVM, minting from `address_B`. The attacker has effectively swapped token identities and can drain whichever token has higher value.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L162-172)
```text
        address bridgeTokenProxy = address(
            new ERC1967Proxy(
                tokenImplementationAddress,
                abi.encodeWithSelector(
                    BridgeToken.initialize.selector,
                    metadata.name,
                    metadata.symbol,
                    decimals
                )
            )
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L54-67)
```text
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
```
