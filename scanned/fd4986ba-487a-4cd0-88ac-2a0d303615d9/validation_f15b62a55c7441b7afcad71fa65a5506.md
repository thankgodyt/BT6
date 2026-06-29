### Title
`deployToken` Signed Payload Lacks Chain and Contract Domain Separation, Enabling Cross-Chain Replay — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `deployToken` function in `OmniBridge.sol` verifies a NEAR MPC ECDSA signature over a Borsh-encoded payload that contains only token metadata fields. It omits `block.chainid` and `address(this)`. Because the same `nearBridgeDerivedAddress` (derived from the NEAR MPC key via the fixed path `"bridge-1"`) is used across every EVM deployment, a valid `deployToken` signature observed on one chain is accepted verbatim on every other EVM chain. The identical omission exists in the Starknet `deploy_token` (`MetadataPayload.to_borsh()`) and the Solana `deploy_token` (`DeployTokenPayload.serialize_for_near()`).

---

### Finding Description

**EVM — `OmniBridge.sol` `deployToken`**

The signed preimage is constructed as:

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

The payload commits to `(PayloadType.Metadata, token, name, symbol, decimals)` only. Neither `block.chainid` nor `address(this)` is included.

By contrast, the `finTransfer` function on the same contract **does** include `omniBridgeChainId` twice in its signed payload, demonstrating that the developers are aware of the need for chain binding in transfer messages but did not apply it to `deployToken`. [2](#0-1) 

**Starknet — `bridge_types.cairo` `MetadataPayload.to_borsh()`**

```cairo
fn to_borsh(self: @MetadataPayload) -> ByteArray {
    let mut borsh_bytes: ByteArray = Default::default();
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
    borsh_bytes
}
``` [3](#0-2) 

No chain ID is included. The Starknet CLAUDE.md explicitly acknowledges that chain ID binding is only applied to `fin_transfer`, not `deploy_token`:

> "Chain ID binding: Destination chain_id encoded in message hash (not in payload) - prevents cross-chain replay" [4](#0-3) 

The `_verify_borsh_signature` helper verifies against `omni_bridge_derived_address` (an Ethereum address), using the same secp256k1/keccak scheme as the EVM contracts. [5](#0-4) 

**Solana — `deploy_token.rs` `DeployTokenPayload.serialize_for_near()`**

```rust
fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
    IncomingMessageType::Metadata.serialize(&mut writer)?;
    self.serialize(&mut writer)?; // borsh encoding
    ...
}
``` [6](#0-5) 

No chain ID or program ID is included. The `verify_signature` function hashes the serialized bytes with keccak256 and recovers against `derived_near_bridge_address`. [7](#0-6) 

**Same signing key across all chains**

The NEAR hub signs all outbound messages using the fixed derivation path `"bridge-1"`: [8](#0-7) 

This means the same `nearBridgeDerivedAddress` / `omni_bridge_derived_address` / `derived_near_bridge_address` is used on every spoke chain. The EVM and Starknet spokes both use Ethereum-style ECDSA over keccak256, and the Borsh encoding of `MetadataPayload` is byte-for-byte identical between the two, making cross-chain replay between EVM chains and Starknet directly feasible.

---

### Impact Explanation

**Unauthorized cross-chain token deployment.** An attacker observes a legitimate `deployToken` transaction on Ethereum (signature `S`, payload `P`). Because `P` contains no chain identifier, `S` is valid on Arbitrum, Base, Polygon, BNB, and Starknet. The attacker submits `(S, P)` to any of those contracts and the signature check passes.

**Permanent blocking of official deployment.** After the replay, the target chain's mapping is populated:

```solidity
require(!isBridgeToken[nearToEthToken[metadata.token]], "ERR_TOKEN_EXIST");
``` [9](#0-8) 

The NEAR bridge can never officially deploy that token on the target chain. The token is permanently registered under an attacker-triggered, unmonitored deployment.

**Permanent freezing of user funds.** Users who call `initTransfer` on the unauthorized deployment lock real tokens in the bridge vault. Because NEAR does not recognize the unauthorized chain/deployment for that token, the corresponding NEAR-side `fin_transfer` will fail or never be submitted by the relayer. The locked tokens are irrecoverable.

---

### Likelihood Explanation

The attack requires no special privileges. Every `deployToken` transaction is publicly visible on-chain. The attacker needs only to copy the calldata (signature + metadata payload) and submit it to any other EVM or Starknet bridge contract. The Borsh encoding of `MetadataPayload` is identical across EVM and Starknet, so a single signature is replayable across all spoke chains simultaneously.

---

### Recommendation

Include `block.chainid` and `address(this)` in the EVM `deployToken` signed preimage:

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeUint64(uint64(block.chainid)),
    Borsh.encodeAddress(address(this)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
);
```

Apply the equivalent fix to `MetadataPayload.to_borsh()` in `starknet/src/bridge_types.cairo` (append `omni_bridge_chain_id` and the contract address) and to `DeployTokenPayload.serialize_for_near()` in `solana/programs/bridge_token_factory/src/state/message/deploy_token.rs` (append `SOLANA_OMNI_BRIDGE_CHAIN_ID` and the program ID). The NEAR hub must include the same fields when constructing the payload it signs, so that signatures are chain- and deployment-specific.

---

### Proof of Concept

1. Observe a legitimate `deployToken(sigEth, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` transaction on Ethereum mainnet. Extract `sigEth`.
2. Call `deployToken(sigEth, {token:"usdc.near", name:"USD Coin", symbol:"USDC", decimals:6})` on the Arbitrum `OmniBridge` contract.
3. `ECDSA.recover(keccak256(borshEncoded), sigEth)` returns `nearBridgeDerivedAddress` (same key, same payload bytes, same hash). Signature check passes.
4. `"usdc.near"` is now registered as a bridge token on Arbitrum under an attacker-triggered deployment. `ERR_TOKEN_EXIST` permanently blocks any future official deployment.
5. Any user who calls `initTransfer` on Arbitrum for this token has their funds locked with no NEAR-side counterpart to release them.

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

**File:** starknet/CLAUDE.md (L45-45)
```markdown
1. **Chain ID binding**: Destination chain_id encoded in message hash (not in payload) - prevents cross-chain replay
```

**File:** starknet/src/omni_bridge.cairo (L398-406)
```text
    fn _verify_borsh_signature(
        ref self: ContractState, borsh_bytes: @ByteArray, signature: Signature,
    ) {
        let message_hash_le = compute_keccak_byte_array(borsh_bytes);
        let message_hash = reverse_u256_bytes(message_hash_le);

        let sig = signature_from_vrs(signature.v, signature.r, signature.s);
        verify_eth_signature(message_hash, sig, self.omni_bridge_derived_address.read());
    }
```

**File:** solana/programs/bridge_token_factory/src/state/message/deploy_token.rs (L19-26)
```rust
    fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
        IncomingMessageType::Metadata.serialize(&mut writer)?;
        self.serialize(&mut writer)?; // borsh encoding
        writer
            .into_inner()
            .map_err(|_| error!(ErrorCode::InvalidArgs))
    }
```

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L24-47)
```rust
    pub fn verify_signature(
        &self,
        params: P::AdditionalParams,
        derived_near_bridge_address: &[u8; 64],
    ) -> Result<()> {
        let serialized = self.payload.serialize_for_near(params)?;
        let hash = keccak::hash(&serialized);

        let signature_bytes = &self.signature[0..64];

        let signature = libsecp256k1::Signature::parse_standard_slice(signature_bytes)
            .map_err(|_| ProgramError::InvalidArgument)?;
        require!(!signature.s.is_high(), ErrorCode::MalleableSignature);

        let signer = secp256k1_recover(&hash.to_bytes(), self.signature[64], signature_bytes)
            .map_err(|_| error!(ErrorCode::SignatureVerificationFailed))?;

        require!(
            signer.0 == *derived_near_bridge_address,
            ErrorCode::SignatureVerificationFailed
        );

        Ok(())
    }
```

**File:** near/omni-bridge/src/lib.rs (L84-84)
```rust
const SIGN_PATH: &str = "bridge-1";
```
