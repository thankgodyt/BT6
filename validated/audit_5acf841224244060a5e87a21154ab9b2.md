### Title
Missing Chain Domain Separation in `deployToken` Signature Enables Cross-Chain Replay — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` verifies a NEAR-MPC signature over a Borsh-encoded message that contains **no chain identifier** — neither the EVM `block.chainid` nor the bridge's own `omniBridgeChainId`. Because the bridge is deployed on multiple EVM chains (Ethereum, Arbitrum, Base, BNB, Polygon, HyperEVM, Abstract, Fogo) all sharing the same `nearBridgeDerivedAddress`, a single valid `deployToken` signature produced for one chain is cryptographically valid on every other chain. An unprivileged attacker can replay it to deploy bridge tokens on chains the NEAR bridge never authorized.

---

### Finding Description

`deployToken` constructs its hash as:

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

The five fields encoded are: payload type tag, NEAR token ID, name, symbol, decimals. **No chain identifier appears anywhere in this hash.**

Contrast this with `finTransfer`, which explicitly encodes `omniBridgeChainId` twice (for the token chain and the recipient chain):

```solidity
bytes1(omniBridgeChainId),
Borsh.encodeAddress(payload.tokenAddress),
...
bytes1(omniBridgeChainId),
Borsh.encodeAddress(payload.recipient),
``` [2](#0-1) 

The `omniBridgeChainId` is a fixed 1-byte value set at initialization and never updated: [3](#0-2) 

The bridge is deployed on at least eight distinct EVM environments, all using the same `nearBridgeDerivedAddress` signer, as evidenced by the `OmniAddress` chain variants: [4](#0-3) 

---

### Impact Explanation

Once a `deployToken` signature is broadcast on chain A (e.g., Ethereum), an attacker can submit the identical `(signatureData, metadata)` tuple to the bridge on chain B (e.g., Arbitrum). The signature check passes because the hash is chain-agnostic. The result:

1. A `BridgeToken` proxy is deployed on chain B and registered in `isBridgeToken`, `ethToNearToken`, and `nearToEthToken`.
2. The `DeployToken` event is emitted on chain B, which the NEAR bridge's event indexer will observe and treat as a legitimate deployment.
3. The NEAR bridge will subsequently generate valid `finTransfer` signatures targeting chain B's `omniBridgeChainId` and the replayed token address, enabling minting on chain B.
4. Critically, the legitimate `deployToken` call for chain B will now **revert** (`"ERR_TOKEN_EXIST"`), permanently preventing the NEAR bridge from deploying a different (possibly corrected or upgraded) token contract for that NEAR token on chain B. [5](#0-4) 

This constitutes a **chain/domain separation flaw**: a signature scoped to one chain is accepted on all chains, violating the domain-binding guarantee that is the entire purpose of including a chain identifier in signed messages.

---

### Likelihood Explanation

- The attack requires only observing a public `deployToken` transaction on any supported EVM chain and submitting the same calldata to another chain's bridge contract.
- No privileged access, leaked keys, or off-chain collusion is needed.
- The bridge is live on multiple EVM chains simultaneously, making the replay surface large.
- The attacker's only cost is the gas to call `deployToken` on the target chain.

---

### Recommendation

Include `omniBridgeChainId` in the `deployToken` Borsh-encoded message, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
+   bytes1(omniBridgeChainId),          // bind signature to this chain
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

The NEAR MPC signer must include the destination `omniBridgeChainId` when producing `deployToken` signatures, so that a signature for Ethereum is cryptographically distinct from one for Arbitrum.

---

### Proof of Concept

1. NEAR bridge generates a `deployToken` signature `σ` for NEAR token `"usdc.near"` targeting Ethereum (`omniBridgeChainId = 1`). The signed hash is `keccak256(Metadata || "usdc.near" || "USD Coin" || "USDC" || 6)`.
2. Attacker observes the Ethereum `deployToken(σ, metadata)` transaction.
3. Attacker submits the identical call to the Arbitrum bridge (`omniBridgeChainId = 2`). The hash computed on Arbitrum is **identical** to the Ethereum hash (no chain field), so `ECDSA.recover` returns `nearBridgeDerivedAddress` and the check passes.
4. A `BridgeToken` proxy for `"usdc.near"` is deployed on Arbitrum and registered as a bridge token.
5. The NEAR bridge's indexer sees the `DeployToken` event on Arbitrum and begins routing Arbitrum-bound USDC transfers to this token.
6. Any subsequent legitimate attempt by the NEAR bridge to deploy `"usdc.near"` on Arbitrum reverts with `"ERR_TOKEN_EXIST"`, locking in the attacker-triggered deployment permanently. [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L72-79)
```text
    function initialize(
        address tokenImplementationAddress_,
        address nearBridgeDerivedAddress_,
        uint8 omniBridgeChainId_
    ) public initializer {
        tokenImplementationAddress = tokenImplementationAddress_;
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
        omniBridgeChainId = omniBridgeChainId_;
```

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

**File:** near/omni-types/src/lib.rs (L275-291)
```rust
    pub fn encode(&self, separator: char, skip_zero_address: bool) -> String {
        let (chain_str, address) = match self {
            Self::Eth(address) => ("eth", address.to_string()),
            Self::Near(address) => ("near", address.to_string()),
            Self::Sol(address) => ("sol", address.to_string()),
            Self::Arb(address) => ("arb", address.to_string()),
            Self::Base(address) => ("base", address.to_string()),
            Self::Bnb(address) => ("bnb", address.to_string()),
            Self::Pol(address) => ("pol", address.to_string()),
            Self::HyperEvm(address) => ("hlevm", address.to_string()),
            Self::Btc(address) => ("btc", address.clone()),
            Self::Zcash(address) => ("zcash", address.clone()),
            Self::Strk(address) => ("strk", address.to_string()),
            Self::Abs(address) => ("abs", address.to_string()),
            Self::Fogo(address) => ("fogo", address.to_string()),
        };

```
