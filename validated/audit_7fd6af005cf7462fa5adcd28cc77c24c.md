### Title
Signed `finTransfer` and `deployToken` Payloads Lack EVM Chain Binding, Enabling Cross-Chain Signature Replay - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `finTransfer` and `deployToken` functions in `OmniBridge.sol` verify ECDSA signatures over Borsh-encoded payloads that contain no EVM `block.chainid` and no contract address (`address(this)`). `finTransfer` embeds only `omniBridgeChainId` — a single-byte Omni Bridge-internal chain identifier stored as a contract state variable — while `deployToken` embeds **no chain identifier whatsoever**. In a hard-fork scenario (or across any two OmniBridge deployments sharing the same `nearBridgeDerivedAddress` and `omniBridgeChainId`), a signature produced by the NEAR MPC signer for one chain is cryptographically valid on the other, enabling an unprivileged attacker to replay `finTransfer` calls and double-spend bridged assets.

---

### Finding Description

**`finTransfer` — missing EVM chain binding**

`OmniBridge.sol::finTransfer` constructs the signed digest as:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
    Borsh.encodeUint64(payload.destinationNonce),
    bytes1(payload.originChain),
    Borsh.encodeUint64(payload.originNonce),
    bytes1(omniBridgeChainId),          // ← stored state variable, NOT block.chainid
    Borsh.encodeAddress(payload.tokenAddress),
    Borsh.encodeUint128(payload.amount),
    bytes1(omniBridgeChainId),          // ← same stored variable, used twice
    Borsh.encodeAddress(payload.recipient),
    ...
);
bytes32 hashed = keccak256(borshEncoded);
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [1](#0-0) 

`omniBridgeChainId` is a `uint8` set once at `initialize()` and stored in contract state. [2](#0-1) [3](#0-2) 

It is never re-derived from `block.chainid`. The EVM chain ID and the OmniBridge contract address are both absent from the signed message. The `TransferMessagePayload` struct confirms no chain-ID field exists beyond the Omni-internal byte: [4](#0-3) 

**`deployToken` — zero chain binding**

`deployToken` is even more exposed: its signed payload contains only `(PayloadType.Metadata, token, name, symbol, decimals)` — no `omniBridgeChainId`, no `block.chainid`, no contract address, and no nonce:

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
``` [5](#0-4) 

The same signature is therefore valid on every EVM chain where the OmniBridge is deployed with the same `nearBridgeDerivedAddress`, with no fork required.

The Starknet bridge has the identical structural flaw: `MetadataPayload::to_borsh` encodes only `(PayloadType, token, name, symbol, decimals)` with no chain identifier, and `TransferMessagePayload::to_borsh` uses the stored `omni_bridge_chain_id` state variable rather than any native chain ID: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

**Hard-fork double-spend via `finTransfer` replay (Critical)**

When an EVM chain forks (e.g., ETH / ETHPoW), both forks inherit the same contract state, including `omniBridgeChainId` and `completedTransfers`. After the fork:

1. A user legitimately locks tokens on fork A and the NEAR MPC signer produces a `finTransfer` signature for destination nonce N.
2. The user submits `finTransfer` on fork A; nonce N is marked used on fork A only.
3. An attacker submits the **identical** `(signatureData, payload)` to the OmniBridge on fork B.
4. `ECDSA.recover` returns `nearBridgeDerivedAddress` (the signature is mathematically valid — the digest is identical because `omniBridgeChainId` is the same on both forks).
5. Nonce N is not yet in `completedTransfers` on fork B, so the check passes.
6. Tokens are minted/unlocked on fork B with no corresponding lock on fork B.

The attacker receives bridged assets on fork B for free, constituting a direct double-spend of bridged funds.

**Cross-chain `deployToken` replay (High)**

Because the `deployToken` digest contains no chain identifier, a single MPC-signed metadata approval for token T on Ethereum can be submitted to the OmniBridge on Arbitrum, Base, BNB, Polygon, or any other supported EVM chain. This:
- Registers the token in the bridge mapping on the target chain without NEAR-side authorization for that specific chain.
- Permanently blocks legitimate deployment on that chain (`require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST")`), freezing the token's bridge path on that chain. [8](#0-7) 

---

### Likelihood Explanation

The `finTransfer` replay requires a hard fork of a supported EVM chain. This is a low-frequency but precedented event (ETH/ETHPoW in 2022 is the canonical example cited in the referenced exploit). The Omni Bridge supports Ethereum, Arbitrum, Base, BNB, Polygon, HyperEVM, and Abstract — any fork of any of these chains triggers the vulnerability.

The `deployToken` replay requires only that the attacker observe a `deployToken` transaction on one chain and submit it to another. This is trivially achievable by any unprivileged actor monitoring public mempool/block data across chains, with no fork required.

---

### Recommendation

Include both `block.chainid` and `address(this)` in every signed payload, mirroring EIP-712 domain separation:

```diff
// finTransfer
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
+   Borsh.encodeUint256(block.chainid),
+   Borsh.encodeAddress(address(this)),
    Borsh.encodeUint64(payload.destinationNonce),
    ...
);

// deployToken
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
+   Borsh.encodeUint256(block.chainid),
+   Borsh.encodeAddress(address(this)),
    Borsh.encodeString(metadata.token),
    ...
);
```

Apply the same fix to the Starknet bridge's `to_borsh` implementations in `bridge_types.cairo`. The NEAR MPC signer must be updated to include these fields when constructing payloads to sign.

---

### Proof of Concept

**`finTransfer` hard-fork replay:**

```
Pre-condition: Ethereum forks at block F. Both forks share contract state.

1. Alice calls initTransfer on fork-A, locking 1000 USDC.
2. NEAR MPC signer produces signature S over:
     keccak256(abi.encodePacked(
       PayloadType.TransferMessage,   // 0x00
       uint64(destinationNonce=42),
       uint8(originChain=0),          // Eth
       uint64(originNonce=1),
       uint8(omniBridgeChainId=0),    // Eth — same on both forks
       address(USDC),
       uint128(1000e6),
       uint8(omniBridgeChainId=0),
       address(Alice),
       ...
     ))
3. Alice submits finTransfer(S, payload) on fork-A. Nonce 42 marked used on fork-A.
4. Attacker submits finTransfer(S, payload) on fork-B.
   - ECDSA.recover(hash, S) == nearBridgeDerivedAddress ✓ (digest identical)
   - completedTransfers[42] == false on fork-B ✓
   - 1000 USDC minted/unlocked to Alice on fork-B with no lock on fork-B.
```

**`deployToken` cross-chain replay:**

```
1. Observe deployToken(S, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})
   on Ethereum mainnet (tx hash T).
2. Submit the identical calldata to OmniBridge on Arbitrum.
   - Digest is identical (no chain ID in payload).
   - ECDSA.recover returns nearBridgeDerivedAddress ✓
   - Token deployed and registered on Arbitrum without NEAR-side authorization for Arbitrum.
   - Subsequent legitimate deployToken call on Arbitrum reverts with "ERR_TOKEN_EXIST".
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L42-43)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L289-313)
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
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L5-14)
```text
    struct TransferMessagePayload {
        uint64 destinationNonce;
        uint8 originChain;
        uint64 originNonce;
        address tokenAddress;
        uint128 amount;
        address recipient;
        string feeRecipient;
        bytes message;
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

**File:** starknet/src/bridge_types.cairo (L61-84)
```text
    fn to_borsh(self: @TransferMessagePayload, chain_id: u8) -> ByteArray {
        let mut borsh_bytes: ByteArray = Default::default();
        borsh_bytes.append_byte(PayloadType::TransferMessage.into());
        borsh_bytes.append(@borsh::encode_u64(*self.destination_nonce));
        borsh_bytes.append_byte(*self.origin_chain);
        borsh_bytes.append(@borsh::encode_u64(*self.origin_nonce));
        borsh_bytes.append_byte(chain_id);
        borsh_bytes.append(@borsh::encode_address(*self.token_address));
        borsh_bytes.append(@borsh::encode_u128(*self.amount));
        borsh_bytes.append_byte(chain_id);
        borsh_bytes.append(@borsh::encode_address(*self.recipient));
        match self.fee_recipient {
            Option::None => { borsh_bytes.append_byte(0); },
            Option::Some(fee_recipient) => {
                borsh_bytes.append_byte(1);
                borsh_bytes.append(@borsh::encode_byte_array(fee_recipient));
            },
        }
        match self.message {
            Option::None => {},
            Option::Some(message) => { borsh_bytes.append(@borsh::encode_byte_array(message)); },
        }
        borsh_bytes
    }
```
