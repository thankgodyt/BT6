The code confirms this is a real vulnerability. Here is the full analysis:

---

### Title
Missing Chain-ID Binding in `MetadataPayload` Signature Enables Cross-Chain Replay of `deployToken` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

The Borsh-encoded payload that the NEAR MPC key signs for `deployToken` contains no destination chain identifier. An attacker who obtains a valid `deployToken` signature for one EVM chain can replay it verbatim on any other EVM chain (or Starknet) that shares the same `nearBridgeDerivedAddress`, deploying an unbacked phantom bridge token.

### Finding Description

In `OmniBridge.sol`, `deployToken` constructs the signed message as:

```
PayloadType.Metadata | encodeString(token) | encodeString(name) | encodeString(symbol) | decimals
``` [1](#0-0) 

The `MetadataPayload` struct itself contains only `token`, `name`, `symbol`, and `decimals` — no chain ID field: [2](#0-1) 

The NEAR-side `MetadataPayload` that is Borsh-serialized and submitted to the MPC signer is identical — `prefix`, `token`, `name`, `symbol`, `decimals` — with no chain binding: [3](#0-2) 

The same absence exists in the Starknet `MetadataPayload.to_borsh()`: [4](#0-3) 

**Contrast with `finTransfer`**, which correctly embeds `omniBridgeChainId` twice in its signed payload (for token address and recipient address chain fields), providing chain binding: [5](#0-4) 

The only replay guard in `deployToken` is `ERR_TOKEN_EXIST`, which only prevents re-deployment on the **same** chain — it does nothing to prevent replay on a **different** chain: [6](#0-5) 

### Impact Explanation

Once a phantom bridge token is deployed on chain B via replayed signature, it is registered in `isBridgeToken`, `ethToNearToken`, and `nearToEthToken` mappings. Any subsequent `finTransfer` call on chain B that references this token address will mint tokens from it — tokens that have no NEAR-side escrow backing. This constitutes unauthorized minting of bridged funds. [7](#0-6) 

### Likelihood Explanation

The precondition — two `OmniBridgeWormhole` deployments sharing the same `nearBridgeDerivedAddress` — is the **intended production deployment model**: the NEAR MPC key is a single global key used across all supported EVM chains. The `initializeWormhole` function accepts `nearBridgeDerivedAddress` as a parameter and there is no mechanism preventing the same address from being used on multiple chains: [8](#0-7) 

Any relayer or observer who sees a valid `deployToken` transaction on chain A can immediately replay it on chain B. No privileged access is required.

### Recommendation

Include `omniBridgeChainId` in the Borsh-encoded `MetadataPayload` before it is submitted to the MPC signer on NEAR, and verify it on the EVM side. The fix mirrors what `finTransfer` already does:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
+   bytes1(omniBridgeChainId),          // chain binding
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

The NEAR `MetadataPayload` struct and its Borsh serialization must be updated to include the destination `ChainKind`, and the MPC signing call in `log_metadata_callback` must pass the target chain. [9](#0-8) 

### Proof of Concept

1. Deploy two `OmniBridgeWormhole` instances — one on Arbitrum (`chainId=2`), one on Optimism (`chainId=3`) — both initialized with the same `nearBridgeDerivedAddress` (the MPC-derived key).
2. On NEAR, call `log_metadata("token.near")`. The MPC signer produces a signature `sig` over `keccak256(borsh(Metadata | "token.near" | "Token" | "TKN" | 18))`.
3. Call `deployToken(sig, {token:"token.near", name:"Token", symbol:"TKN", decimals:18})` on Arbitrum — succeeds legitimately.
4. Call `deployToken(sig, {token:"token.near", name:"Token", symbol:"TKN", decimals:18})` on Optimism with the **identical** `sig` — also succeeds, because the hash is identical (no chain ID in the payload).
5. Assert `nearToEthToken["token.near"]` is set on Optimism to a freshly deployed `BridgeToken` with no NEAR-side backing.
6. Confirm by diffing `keccak256(borshEncoded)` across both chain instances — they are equal, proving no chain-binding field exists.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L190-192)
```text
        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);
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

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L16-21)
```text
    struct MetadataPayload {
        string token;
        string name;
        string symbol;
        uint8 decimals;
    }
```

**File:** near/omni-types/src/lib.rs (L694-702)
```rust
#[near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct MetadataPayload {
    pub prefix: PayloadType,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L32-46)
```text
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

**File:** near/omni-bridge/src/lib.rs (L341-360)
```rust
        let metadata_payload = MetadataPayload {
            prefix: PayloadType::Metadata,
            token: token_id.to_string(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
        };

        let payload = near_sdk::env::keccak256_array(
            borsh::to_vec(&metadata_payload).near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
```
