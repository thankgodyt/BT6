### Title
Missing Chain-ID Binding in `deployToken` Signature Allows Cross-Chain Replay — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` verifies a NEAR-MPC-derived ECDSA signature over a borsh-encoded payload that contains **no chain identifier and no contract address**. Because the same `OmniBridge` contract is deployed on multiple EVM chains (Ethereum, Arbitrum, Base, Polygon, BNB), a valid `deployToken` signature obtained for one chain can be replayed verbatim on every other chain, deploying the same bridge token without any per-chain authorization from NEAR.

---

### Finding Description

`OmniBridge.sol` exposes two signature-verified entry points. Their signed payloads differ critically:

**`finTransfer` — chain-bound (correct):** [1](#0-0) 

The borsh blob includes `omniBridgeChainId` at two positions (token address prefix and recipient prefix), binding the signature to the specific deployment chain.

**`deployToken` — NOT chain-bound (vulnerable):** [2](#0-1) 

The borsh blob is:
```
PayloadType.Metadata | encodeString(token) | encodeString(name) | encodeString(symbol) | bytes1(decimals)
```

No `omniBridgeChainId`, no `address(this)`, no nonce. The hash and the recovered signer are identical on every EVM chain where `OmniBridge` is deployed with the same `nearBridgeDerivedAddress`.

The contract stores `omniBridgeChainId` as a state variable set at initialization: [3](#0-2) [4](#0-3) 

It is used in `finTransfer` but never included in the `deployToken` payload.

---

### Impact Explanation

An attacker who observes a valid `deployToken(signatureData, metadata)` call on any one EVM chain (e.g., Ethereum) can immediately replay the identical calldata on every other OmniBridge deployment (Arbitrum, Base, Polygon, BNB). Each replay:

1. Passes signature verification (same hash, same signer).
2. Deploys a `BridgeToken` proxy on that chain and registers it in `nearToEthToken` / `isBridgeToken`.
3. Permanently blocks the bridge operator from ever legitimately deploying that token on those chains (`ERR_TOKEN_EXIST` guard prevents re-deployment). [5](#0-4) 

The deployed token is a real, mintable `BridgeToken` controlled by the bridge contract. Once registered, the bridge on that chain will mint/burn it for any `finTransfer` call that passes signature verification. If NEAR subsequently registers decimals for that token (e.g., via a `log_metadata` flow), the attacker-seeded token becomes fully operational on chains the operator never intended to activate, constituting an unauthorized bridge action and a chain/domain separation flaw.

---

### Likelihood Explanation

All `deployToken` calls are public on-chain transactions. Any observer of any supported EVM chain can extract the `signatureData` and `metadata` arguments from the transaction calldata and resubmit them to every other OmniBridge deployment. No privileged access, no leaked keys, and no off-chain coordination are required. The attack is executable by any unprivileged user immediately after the first legitimate `deployToken` transaction is mined.

---

### Recommendation

Include `omniBridgeChainId` (and optionally `address(this)`) in the borsh-encoded payload that is hashed and signed for `deployToken`, mirroring the pattern already used in `finTransfer`:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeChainId),          // ADD: chain binding
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

The NEAR signing logic must be updated in parallel to include the destination chain ID when producing `deployToken` signatures, so that each signature is valid on exactly one chain.

---

### Proof of Concept

1. Bridge operator calls `deployToken(sig, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` on Ethereum (`omniBridgeChainId = 2`). Transaction is mined and publicly visible.
2. Attacker copies `sig` and the `metadata` struct verbatim.
3. Attacker calls `deployToken(sig, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` on Arbitrum (`omniBridgeChainId = 3`).
4. `keccak256(borshEncoded)` is identical on both chains because `omniBridgeChainId` is absent from the payload.
5. `ECDSA.recover` returns `nearBridgeDerivedAddress` on Arbitrum — signature check passes. [6](#0-5) 
6. A `BridgeToken` for `usdc.near` is deployed and registered on Arbitrum without any authorization from NEAR for that chain.
7. The operator can never legitimately deploy `usdc.near` on Arbitrum again; the `ERR_TOKEN_EXIST` guard permanently blocks it. [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L42-42)
```text
    uint8 public omniBridgeChainId;
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-311)
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

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
```
