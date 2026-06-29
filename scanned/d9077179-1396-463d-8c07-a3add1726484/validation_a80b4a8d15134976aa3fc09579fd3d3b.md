### Title
Missing Domain Separator in `deployToken()` Signed Hash Enables Cross-Chain Signature Replay — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken()` function in `OmniBridge.sol` verifies a NEAR MPC signature over a Borsh-encoded metadata payload that contains no chain identifier (`block.chainid`) and no contract address (`address(this)`). Because the NEAR MPC derives the same secp256k1 address (`nearBridgeDerivedAddress`) for all EVM destination chains using the fixed path `"bridge-1"`, a valid `deployToken` signature produced for one EVM chain (e.g., Ethereum) is cryptographically identical and replayable on every other EVM chain where an `OmniBridge` instance is deployed (e.g., Base, Arbitrum, Polygon, BNB).

---

### Finding Description

In `deployToken()`, the signed hash is constructed as:

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

The hash binds only to the token metadata fields. It does not bind to:
- `address(this)` — the specific `OmniBridge` contract instance
- `block.chainid` — the EVM chain the signature is intended for
- `omniBridgeChainId` — the bridge's own chain identifier (which is included in `finTransfer` but absent here)

The NEAR bridge contract signs all outbound payloads using the fixed path `SIGN_PATH = "bridge-1"`: [2](#0-1) 

This means the MPC-derived secp256k1 address (`nearBridgeDerivedAddress`) is identical across every EVM chain. A signature over `(PayloadType.Metadata, token, name, symbol, decimals)` is therefore valid on all chains simultaneously.

By contrast, `finTransfer()` does include `omniBridgeChainId` in its hash (providing some chain separation), but `deployToken()` includes no chain binding whatsoever: [3](#0-2) 

---

### Impact Explanation

An attacker who observes a legitimate `deployToken` transaction on chain A (e.g., Ethereum) can extract the `signatureData` and `metadata` arguments and submit an identical call to `OmniBridge` on chain B (e.g., Base, Arbitrum, Polygon). The signature check passes because `nearBridgeDerivedAddress` is the same on all chains and the hash is chain-agnostic.

Consequences:

1. **Unauthorized token deployment**: The attacker deploys a bridged token on chain B before the bridge operator intends to, establishing the `nearToEthToken` / `ethToNearToken` mapping.
2. **Blocking legitimate deployment**: Once `nearToEthToken[metadata.token]` is set, the check `require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST")` permanently prevents the operator from deploying the same NEAR token on chain B with different parameters (e.g., a different `tokenImplementationAddress` or corrected metadata). [4](#0-3) 
3. **Token metadata binding confusion**: If the operator later discovers the pre-deployed token is misconfigured (e.g., wrong decimal normalization for that chain's conventions), they cannot redeploy — the mapping is permanently poisoned.
4. **Cross-function replay surface**: Because `deployToken` and `finTransfer` share the same `nearBridgeDerivedAddress` signer but use different `PayloadType` prefixes, the absence of `address(this)` also means a `deployToken` signature is replayable across any two `OmniBridge`-derived contracts on the same chain (e.g., `OmniBridge` and `OmniBridgeWormhole`) if their payload encodings collide. [5](#0-4) 

---

### Likelihood Explanation

- The attack requires only observing a publicly emitted `DeployToken` event or a pending mempool transaction on any one EVM chain — no privileged access, no leaked keys.
- The attacker needs only to copy `signatureData` and `metadata` and call `deployToken()` on a different chain's `OmniBridge` contract.
- The NEAR MPC signing path is hardcoded to `"bridge-1"` for all chains, making the same `nearBridgeDerivedAddress` a certainty across all EVM deployments.
- The bridge is deployed on multiple EVM chains (Ethereum, Base, Arbitrum, Polygon, BNB per the README), so the replay surface is wide.

---

### Recommendation

Include both `address(this)` and `block.chainid` in the signed hash for `deployToken()`, mirroring the pattern already partially used in `finTransfer()` (which includes `omniBridgeChainId`). Ideally adopt EIP-712 typed structured data hashing with a proper domain separator:

```solidity
bytes32 domainSeparator = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
    keccak256("OmniBridge"),
    block.chainid,
    address(this)
));
```

Apply the same fix to `finTransfer()` (which currently omits `address(this)`) to prevent cross-contract replay between `OmniBridge` and `OmniBridgeWormhole` instances on the same chain.

---

### Proof of Concept

1. The NEAR bridge operator calls `deployToken(sig, {token: "usdc.near", name: "USD Coin", symbol: "USDC", decimals: 6})` on Ethereum `OmniBridge` at block N. The MPC signs `keccak256(Metadata || "usdc.near" || "USD Coin" || "USDC" || 0x06)`.

2. Attacker observes the transaction, extracts `sig` and `metadata`.

3. Attacker calls `deployToken(sig, {token: "usdc.near", name: "USD Coin", symbol: "USDC", decimals: 6})` on the Base `OmniBridge`.

4. `ECDSA.recover(keccak256(same_borsh_encoding), sig)` returns the same `nearBridgeDerivedAddress` — the check passes. [6](#0-5) 

5. A `BridgeToken` proxy is deployed on Base, `nearToEthToken["usdc.near"]` is set, and `isBridgeToken[proxy] = true`. [7](#0-6) 

6. The bridge operator can never redeploy `"usdc.near"` on Base — `require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST")` will always revert. [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-195)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
        if (tokenImplementationAddress == address(0)) {
            revert TokenImplementationNotSet();
        }
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

        require(
            !isBridgeToken[nearToEthToken[metadata.token]],
            "ERR_TOKEN_EXIST"
        );
        uint8 decimals = _normalizeDecimals(metadata.decimals);

        // slither-disable-next-line reentrancy-no-eth
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

        deployTokenExtension(
            metadata.token,
            bridgeTokenProxy,
            decimals,
            metadata.decimals
        );

        emit BridgeTypes.DeployToken(
            bridgeTokenProxy,
            metadata.token,
            metadata.name,
            metadata.symbol,
            decimals,
            metadata.decimals
        );

        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);

        return bridgeTokenProxy;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-309)
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
        bytes32 hashed = keccak256(borshEncoded);
```

**File:** near/omni-bridge/src/lib.rs (L84-84)
```rust
const SIGN_PATH: &str = "bridge-1";
```
