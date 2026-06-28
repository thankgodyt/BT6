### Title
`deployToken` Uses `CREATE` With Replay-Vulnerable Signature, Enabling Reorg-Based Token Address Hijack — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.deployToken` deploys bridge token proxies via `new ERC1967Proxy(...)` (the `CREATE` opcode), whose address depends solely on the `OmniBridge` contract's nonce. The MPC signature authorizing the deployment contains no nonce, no chain ID, and no expiry, making it freely replayable by any observer. On the reorg-susceptible chains where `OmniBridgeWormhole` is deployed (Polygon, Arbitrum, Base), an attacker can replay the same signature after a reorg to deploy the bridge token at a different address, corrupting the NEAR-side token mapping and causing users who already received tokens at the pre-reorg address to hold worthless assets.

---

### Finding Description

`deployToken` in `OmniBridge.sol` constructs the signed payload as:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
``` [1](#0-0) 

The payload contains **no nonce, no chain ID, and no expiry**. The signature is verified against `nearBridgeDerivedAddress` but is never consumed or invalidated after use: [2](#0-1) 

The only guard against re-deployment is:

```solidity
require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST");
``` [3](#0-2) 

This guard is wiped by a reorg. After the reorg, `nearToEthToken[metadata.token]` is `address(0)` again, so the check passes and the same signature can be used to deploy a second proxy.

The proxy itself is deployed with plain `new`:

```solidity
address bridgeTokenProxy = address(
    new ERC1967Proxy(
        tokenImplementationAddress,
        abi.encodeWithSelector(...)
    )
);
``` [4](#0-3) 

Because `CREATE` derives the address from `(deployer, nonce)`, any change in the `OmniBridge` contract's nonce between the original and the replayed call produces a **different token address**.

`OmniBridgeWormhole` inherits `deployToken` unchanged and is the variant deployed on Polygon, Arbitrum, and Base: [5](#0-4) 

---

### Impact Explanation

**Critical — permanent loss of bridged funds.**

After a reorg:

1. The pre-reorg `DeployToken` Wormhole VAA (carrying address X) may already have been processed by the NEAR bridge, which recorded X as the canonical EVM address for the NEAR token.
2. The attacker replays the signature, deploying the token at address Y.
3. The NEAR bridge now emits a second `DeployToken` VAA for Y, creating an inconsistent or overwritten mapping.
4. Any user who received bridge tokens minted at address X (before the reorg) now holds tokens at a contract that is no longer recognized as a bridge token — those tokens cannot be burned to initiate a return transfer, and `finTransfer` calls from NEAR will mint to Y, not X.
5. The tokens at X are permanently stranded.

Additionally, because the signature contains no chain ID, the same MPC-signed payload is valid on every EVM chain where `OmniBridge` is deployed with the same `nearBridgeDerivedAddress`, enabling cross-chain replay to deploy the same NEAR token at attacker-chosen nonce-derived addresses on other chains.

---

### Likelihood Explanation

Polygon has publicly documented reorgs lasting over 1.5 minutes. Arbitrum and Base (optimistic rollups) are subject to fraud-proof-driven block reversions. The attacker entry path requires only:

- Observing a pending `deployToken` transaction in the mempool (trivially done),
- Waiting for a reorg (a known, recurring event on these chains),
- Replaying the identical calldata with the same signature.

No privileged access, no key compromise, and no admin cooperation is required.

---

### Recommendation

1. **Use `CREATE2` with a deterministic salt** derived from `metadata.token` (the NEAR token ID), so the deployed address is independent of the contract nonce and identical across any number of deployment attempts:

```solidity
bytes32 salt = keccak256(abi.encodePacked(metadata.token));
address bridgeTokenProxy = address(
    new ERC1967Proxy{salt: salt}(
        tokenImplementationAddress,
        abi.encodeWithSelector(BridgeToken.initialize.selector, ...)
    )
);
```

2. **Include a chain ID and a per-deployment nonce in the MPC-signed payload** to prevent cross-chain replay and mempool-replay of the same signature.

---

### Proof of Concept

**Setup**: `OmniBridgeWormhole` is deployed on Polygon at nonce N. The NEAR MPC produces a valid signature `sig` for token `"near:usdc.near"`.

1. Relayer submits `deployToken(sig, metadata)` → `ERC1967Proxy` deployed at address **X** (nonce N). `DeployToken` Wormhole VAA emitted with address X. NEAR bridge processes VAA, sets `nearToEthToken["near:usdc.near"] = X`.

2. Users bridge NEAR USDC → Polygon. `finTransfer` mints tokens at X. Users hold X-tokens.

3. Polygon reorg occurs (reverts the block containing step 1). `isBridgeToken[X]` and `nearToEthToken["near:usdc.near"]` are reset to zero/empty.

4. Attacker submits `deployToken(sig, metadata)` (same signature, no nonce check). `OmniBridge` nonce is now N+k (other transactions occurred). `ERC1967Proxy` deployed at address **Y ≠ X**. New `DeployToken` VAA emitted with address Y.

5. NEAR bridge processes the new VAA, overwrites mapping: `nearToEthToken["near:usdc.near"] = Y`.

6. All future `finTransfer` calls mint at Y. Tokens previously minted at X are permanently non-redeemable — users from step 2 have lost their funds.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L151-158)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L26-46)
```text
contract OmniBridgeWormhole is OmniBridge {
    IWormhole private _wormhole;
    // https://wormhole.com/docs/build/reference/consistency-levels
    uint8 private _consistencyLevel;
    uint32 public wormholeNonce;

    function initializeWormhole(
        address tokenImplementationAddress,
        address nearBridgeDerivedAddress,
        uint8 omniBridgeChainId,
        address wormholeAddress,
        uint8 consistencyLevel
    ) external initializer {
        initialize(
            tokenImplementationAddress,
            nearBridgeDerivedAddress,
            omniBridgeChainId
        );
        _wormhole = IWormhole(wormholeAddress);
        _consistencyLevel = consistencyLevel;
    }
```
