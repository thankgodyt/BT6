### Title
Cross-Chain Replay of MPC `deploy_token` Signature Due to Missing `chain_id` in `MetadataPayload` Borsh Encoding — (`starknet/src/bridge_types.cairo`, `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`MetadataPayload::to_borsh` on Starknet and the equivalent Borsh encoding in EVM's `deployToken` both omit a `chain_id` field. Because both chains verify the ECDSA signature against the same MPC-derived address (derived from `SIGN_PATH = "bridge-1"`), a valid MPC signature produced for an EVM `deployToken` call is byte-for-byte identical to what Starknet's `deploy_token` would verify. An attacker can replay the EVM signature on Starknet (or vice versa) to deploy a bridge token on a chain for which the MPC never explicitly authorized deployment.

---

### Finding Description

**Root cause — `MetadataPayload::to_borsh` (Starknet):**

```cairo
fn to_borsh(self: @MetadataPayload) -> ByteArray {
    let mut borsh_bytes: ByteArray = Default::default();
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
    borsh_bytes  // ← no chain_id
}
``` [1](#0-0) 

**Root cause — EVM `deployToken` Borsh encoding:**

```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)  // ← no chain_id
);
bytes32 hashed = keccak256(borshEncoded);
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) revert InvalidSignature();
``` [2](#0-1) 

**Root cause — NEAR `MetadataPayload` struct:**

```rust
pub struct MetadataPayload {
    pub prefix: PayloadType,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,  // ← no chain_id
}
``` [3](#0-2) 

NEAR signs with a single path `SIGN_PATH = "bridge-1"` for all destination chains. [4](#0-3) 

Both EVM (`nearBridgeDerivedAddress`) and Starknet (`omni_bridge_derived_address`) store the Ethereum-style address derived from this same MPC key. [5](#0-4) [6](#0-5) 

Starknet's `_verify_borsh_signature` verifies against `omni_bridge_derived_address` with no chain binding: [7](#0-6) 

**Contrast with `TransferMessagePayload`**, which correctly includes `chain_id` twice in its Borsh encoding: [8](#0-7) 

The `starknet/CLAUDE.md` documents "Chain ID binding: Destination chain_id encoded in message hash (not in payload) - prevents cross-chain replay" as a security property, but this is only implemented for `TransferMessagePayload`, not `MetadataPayload`. [9](#0-8) 

---

### Impact Explanation

An attacker who observes a valid MPC signature submitted to EVM's `deployToken` (which is public on-chain) can submit the identical `(signature, payload)` pair to Starknet's `deploy_token`. The signature passes `_verify_borsh_signature` because the Borsh bytes are identical and the verifying key is the same. The token is then registered in `near_to_starknet_token` and `starknet_to_near_token` as a bridge token (mintable/burnable by the Starknet bridge), without the MPC ever having authorized deployment on Starknet.

The secondary "unbacked minting via `fin_transfer`" claim is **partially overstated**: `fin_transfer` does include `chain_id` in `TransferMessagePayload::to_borsh`, so direct unbacked minting requires a separately valid chain-specific MPC signature. However, the unauthorized deployment itself constitutes a signer/prover verification bypass — the MPC signature is accepted as authorizing Starknet deployment when it only authorized EVM deployment — and creates a persistent state inconsistency (a bridge token exists on Starknet that NEAR's bridge has no record of), which can disrupt bridge accounting and token registry integrity.

---

### Likelihood Explanation

All inputs needed for the replay are public: the `MetadataPayload` fields and the MPC signature are submitted as calldata to EVM's `deployToken` and are readable from any EVM block explorer. No privileged access, key compromise, or threshold MPC collusion is required. The attacker only needs to copy the calldata and submit it to Starknet's `deploy_token`.

---

### Recommendation

Include `chain_id` in `MetadataPayload::to_borsh` on all chains, mirroring the pattern already used in `TransferMessagePayload::to_borsh`. On Starknet:

```cairo
fn to_borsh(self: @MetadataPayload, chain_id: u8) -> ByteArray {
    let mut borsh_bytes: ByteArray = Default::default();
    borsh_bytes.append_byte(PayloadType::Metadata.into());
    borsh_bytes.append_byte(chain_id);  // ← add this
    borsh_bytes.append(@borsh::encode_byte_array(self.token));
    borsh_bytes.append(@borsh::encode_byte_array(self.name));
    borsh_bytes.append(@borsh::encode_byte_array(self.symbol));
    borsh_bytes.append_byte(*self.decimals);
    borsh_bytes
}
```

Apply the same change to EVM's `deployToken` Borsh encoding and to NEAR's `MetadataPayload` Borsh serialization. The NEAR `log_metadata_callback` must pass the target chain's ID when constructing the payload to sign, so each chain receives a chain-specific signature.

---

### Proof of Concept

1. Call `log_metadata` on NEAR for `token.near`. NEAR's MPC signs `keccak256(borsh(MetadataPayload{prefix:1, token:"token.near", name:"Token", symbol:"TKN", decimals:18}))` with path `"bridge-1"`.
2. A relayer submits `(signature, payload)` to EVM's `deployToken`. The token is deployed on EVM. The signature is now public in EVM calldata.
3. An attacker copies the exact `(signature, payload)` and calls Starknet's `deploy_token(signature, payload)`.
4. `_verify_borsh_signature` computes `keccak256(payload.to_borsh())` — identical bytes to step 1 — and verifies against `omni_bridge_derived_address`. The check passes.
5. `token.near` is deployed as a bridge token on Starknet. `near_to_starknet_token[keccak("token.near")]` is now set.
6. Assert: `dispatcher.get_token_address("token.near")` returns a non-zero address on Starknet, confirming deployment without any Starknet-specific MPC authorization.

### Citations

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

**File:** starknet/src/bridge_types.cairo (L61-71)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L41-42)
```text
    address public nearBridgeDerivedAddress;
    uint8 public omniBridgeChainId;
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

**File:** near/omni-bridge/src/lib.rs (L84-84)
```rust
const SIGN_PATH: &str = "bridge-1";
```

**File:** starknet/src/omni_bridge.cairo (L118-118)
```text
        omni_bridge_derived_address: EthAddress,
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

**File:** starknet/CLAUDE.md (L45-45)
```markdown
1. **Chain ID binding**: Destination chain_id encoded in message hash (not in payload) - prevents cross-chain replay
```
