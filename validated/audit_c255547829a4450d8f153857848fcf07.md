### Title
`deployToken` / `deploy_token` Signed `MetadataPayload` Not Bound to Destination Chain Enables Cross-Chain Replay — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`)

---

### Summary

The `MetadataPayload` hash used to authorize token deployments in `deployToken` (EVM) and `deploy_token` (Starknet) does not include a destination chain identifier. Both chains share the same NEAR MPC-derived signing key and use an identical Borsh-encoded hash structure. A valid signature extracted from a public `deployToken` transaction on EVM can be replayed verbatim on Starknet (and vice versa), causing an unauthorized token deployment on the unintended chain without the token owner's consent.

---

### Finding Description

**Root cause — EVM (`OmniBridge.sol`):**

The `deployToken` function constructs the hash as:

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

No chain ID is included. The signer key `nearBridgeDerivedAddress` is the same NEAR MPC-derived address used across all supported chains.

**Root cause — Starknet (`omni_bridge.cairo`):**

The `deploy_token` function verifies:

```cairo
_verify_borsh_signature(ref self, @payload.to_borsh(), signature);
``` [2](#0-1) 

`payload.to_borsh()` produces:

```
bytes1(PayloadType::MetadataPayload) | encode_byte_array(token) | encode_byte_array(name) | encode_byte_array(symbol) | bytes1(decimals)
``` [3](#0-2) 

No chain ID is included. The verifying key `omni_bridge_derived_address` is the same NEAR MPC-derived Ethereum address used on EVM.

**Contrast with `finTransfer`:** The `finTransfer` hash on EVM correctly includes `bytes1(omniBridgeChainId)` before both the token address and the recipient address, binding it to the specific chain. [4](#0-3)  The `fin_transfer` hash on Starknet similarly passes `self.omni_bridge_chain_id.read()` into `payload.to_borsh(chain_id)`. [5](#0-4)  The `deployToken` path has no equivalent binding.

**Encoding equivalence:** Both EVM (`Borsh.encodeString`) and Starknet (`borsh::encode_byte_array`) produce the standard Borsh wire format: 4-byte little-endian length prefix followed by raw UTF-8 bytes. The `PayloadType::Metadata` discriminant byte is `1` on both chains. The hash inputs are therefore byte-for-byte identical for the same `(token, name, symbol, decimals)` tuple.

**Attack path:**

1. Attacker observes a successful `deployToken(signatureData, metadata)` call on EVM (fully public on-chain data).
2. Attacker extracts `signatureData` and `metadata` from the transaction calldata.
3. Attacker calls `deploy_token(signature, payload)` on Starknet with the identical values.
4. `_verify_borsh_signature` passes because the hash is identical and the signing key is the same.
5. The token is deployed on Starknet and registered in `near_to_starknet_token`. [6](#0-5) 
6. Any subsequent legitimate `deploy_token` call for the same NEAR token ID on Starknet reverts with `ERR_TOKEN_ALREADY_DEPLOYED`. [7](#0-6) 

---

### Impact Explanation

An unprivileged attacker can execute token-deployer-equivalent actions on any supported chain by replaying a signature that was authorized only for a different chain. Concretely:

- **Authorization bypass**: The NEAR MPC signed a payload authorizing deployment on chain A. The attacker uses that authorization to deploy on chain B without any additional MPC approval.
- **Permanent blocking**: Once the attacker's replay succeeds, the `near_to_starknet_token` mapping is permanently populated for that NEAR token ID. The legitimate deployer can never deploy the canonical version of that token on Starknet; every attempt reverts with `ERR_TOKEN_ALREADY_DEPLOYED`.
- **Unauthorized bridge token creation**: The attacker-deployed contract on Starknet has the bridge's authority PDA as its controller, meaning the bridge will mint tokens into it during `fin_transfer` calls. The token owner has no control over when or whether their token appears on Starknet.

This satisfies the "authorization bypass that lets an attacker execute token deployer actions" criterion in the allowed impact scope.

---

### Likelihood Explanation

**High.** The attack requires zero privileged access. All inputs (signature bytes and metadata payload) are visible in the calldata of any public `deployToken` transaction on EVM. The replay is a single contract call on Starknet. Any token that has been deployed on EVM but not yet on Starknet is permanently at risk from the moment its EVM deployment transaction is confirmed.

---

### Recommendation

**Short term:** Include the destination chain ID in the `MetadataPayload` hash, mirroring the pattern already used in `finTransfer`.

EVM:
```solidity
bytes memory borshEncoded = bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    bytes1(omniBridgeCh

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

**File:** starknet/src/omni_bridge.cairo (L202-205)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');

            _verify_borsh_signature(ref self, @payload.to_borsh(), signature);
```

**File:** starknet/src/omni_bridge.cairo (L207-209)
```text
            let token_id_hash = compute_keccak_byte_array(@payload.token);
            let existing_token = self.near_to_starknet_token.read(token_id_hash);
            assert(existing_token.is_zero(), 'ERR_TOKEN_ALREADY_DEPLOYED');
```

**File:** starknet/src/omni_bridge.cairo (L224-225)
```text
            self.starknet_to_near_token.write(contract_address, payload.token.clone());
            self.near_to_starknet_token.write(token_id_hash, contract_address);
```

**File:** starknet/src/omni_bridge.cairo (L252-254)
```text
            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );
```

**File:** starknet/tests/test_contract.cairo (L83-93)
```text
fn build_deploy_token_message(payload: @MetadataPayload) -> u256 {
    let mut borsh_bytes: ByteArray = "";
    borsh_bytes.append_byte(1); // PayloadType::MetadataPayload
    borsh_bytes.append(@borsh::encode_byte_array(payload.token));
    borsh_bytes.append(@borsh::encode_byte_array(payload.name));
    borsh_bytes.append(@borsh::encode_byte_array(payload.symbol));
    borsh_bytes.append_byte(*payload.decimals);

    let hash_le = compute_keccak_byte_array(@borsh_bytes);
    reverse_u256_bytes(hash_le)
}
```
